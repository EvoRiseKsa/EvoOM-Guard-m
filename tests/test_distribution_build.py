# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Security tests for the one complete ``evoom-guard`` distribution."""

from __future__ import annotations

import io
import os
import site
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "tools" / "packaging"))

import build_distribution as distribution  # noqa: E402


@pytest.fixture(scope="module")
def canonical_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("single-distribution")
    first = distribution.build(root / "first")
    second = distribution.build(root / "second")
    assert first.read_bytes() == second.read_bytes()
    distribution.audit(first)
    return first


def _contents(wheel: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(wheel) as archive:
        return {info.filename: archive.read(info) for info in archive.infolist()}


def _write_canonical(wheel: Path, contents: dict[str, bytes]) -> None:
    with wheel.open("xb") as raw:
        with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as archive:
            for name in sorted(contents):
                info = zipfile.ZipInfo(name, date_time=distribution.ZIP_TIMESTAMP)
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, contents[name])


def _record_name(contents: dict[str, bytes]) -> str:
    records = [name for name in contents if name.endswith(".dist-info/RECORD")]
    assert len(records) == 1
    return records[0]


def _refresh_record(contents: dict[str, bytes]) -> None:
    record = _record_name(contents)
    without_record = {name: data for name, data in contents.items() if name != record}
    contents[record] = distribution._canonical_record(without_record, record)


def _insert_hidden_zip_padding(raw: bytes) -> bytes:
    end = raw.rfind(b"PK\x05\x06")
    assert end >= 0
    central_offset = int.from_bytes(raw[end + 16 : end + 20], "little")
    assert raw[central_offset : central_offset + 4] == b"PK\x01\x02"
    padding = b"unreviewed bytes between ZIP records"
    mutated = bytearray(raw[:central_offset] + padding + raw[central_offset:])
    moved_end = end + len(padding)
    mutated[moved_end + 16 : moved_end + 20] = (
        central_offset + len(padding)
    ).to_bytes(4, "little")
    return bytes(mutated)


def test_complete_distribution_is_canonical_and_not_a_second_core_package(
    canonical_wheel: Path,
) -> None:
    with zipfile.ZipFile(canonical_wheel) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
    assert canonical_wheel.name.startswith("evoom_guard-")
    assert "core" not in canonical_wheel.name
    assert all("evoom_guard_core" not in name for name in names)
    assert names == sorted(names)
    assert all(info.date_time == distribution.ZIP_TIMESTAMP for info in infos)
    assert all(info.compress_type == zipfile.ZIP_STORED for info in infos)
    assert all((info.external_attr >> 16) & 0xFFFF == 0o100644 for info in infos)
    metadata = next(name for name in names if name.endswith(".dist-info/METADATA"))
    assert b"\r" not in _contents(canonical_wheel)[metadata]


def test_audit_rejects_modified_member_with_stale_record(
    canonical_wheel: Path, tmp_path: Path
) -> None:
    contents = _contents(canonical_wheel)
    contents["evoom_guard/__init__.py"] += b"\n# modified after build\n"
    tampered = tmp_path / canonical_wheel.name
    _write_canonical(tampered, contents)

    with pytest.raises(distribution.DistributionBuildError, match="RECORD digest mismatch"):
        distribution.audit(tampered)


def test_audit_rejects_modified_member_even_with_recomputed_record(
    canonical_wheel: Path, tmp_path: Path
) -> None:
    contents = _contents(canonical_wheel)
    contents["evoom_guard/__init__.py"] += b"\n# forged and re-recorded\n"
    _refresh_record(contents)
    tampered = tmp_path / canonical_wheel.name
    _write_canonical(tampered, contents)

    with pytest.raises(distribution.DistributionBuildError, match="differs from staged source"):
        distribution.audit(tampered)


def test_audit_rejects_hidden_member_even_with_recomputed_record(
    canonical_wheel: Path, tmp_path: Path
) -> None:
    contents = _contents(canonical_wheel)
    contents["evoom_guard/hidden_payload.py"] = b"raise SystemExit('not reviewed')\n"
    _refresh_record(contents)
    tampered = tmp_path / canonical_wheel.name
    _write_canonical(tampered, contents)

    with pytest.raises(distribution.DistributionBuildError, match="member set differs"):
        distribution.audit(tampered)


def test_audit_rejects_appended_payload(canonical_wheel: Path, tmp_path: Path) -> None:
    tampered = tmp_path / canonical_wheel.name
    tampered.write_bytes(canonical_wheel.read_bytes() + b"unreviewed trailing payload")

    with pytest.raises(distribution.DistributionBuildError, match="trailing bytes"):
        distribution.audit(tampered)


def test_audit_rejects_hidden_padding_between_zip_records(
    canonical_wheel: Path, tmp_path: Path
) -> None:
    tampered = tmp_path / canonical_wheel.name
    tampered.write_bytes(_insert_hidden_zip_padding(canonical_wheel.read_bytes()))
    # The padding is legal enough for the stdlib ZIP reader and does not alter
    # members, RECORD, the central directory, or the EOCD position contract.
    assert _contents(tampered) == _contents(canonical_wheel)

    with pytest.raises(distribution.DistributionBuildError, match="raw ZIP bytes"):
        distribution.audit(tampered)


def test_audit_binds_zip_reads_and_final_readback_to_one_snapshot(
    canonical_wheel: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / canonical_wheel.name
    original = canonical_wheel.read_bytes()
    target.write_bytes(original)
    replacement = tmp_path / "replacement.whl"
    replacement.write_bytes(_insert_hidden_zip_padding(original))
    real_zip_file = distribution.zipfile.ZipFile
    replaced = False

    def replace_path_after_snapshot(source, *args, **kwargs):
        nonlocal replaced
        if not replaced:
            assert isinstance(source, io.BytesIO)
            os.replace(replacement, target)
            replaced = True
        return real_zip_file(source, *args, **kwargs)

    monkeypatch.setattr(distribution.zipfile, "ZipFile", replace_path_after_snapshot)

    with pytest.raises(distribution.DistributionBuildError, match="changed after.*snapshot"):
        distribution.audit(target)
    assert replaced


def test_audit_rejects_metadata_tamper_with_recomputed_record(
    canonical_wheel: Path, tmp_path: Path
) -> None:
    contents = _contents(canonical_wheel)
    metadata = next(name for name in contents if name.endswith(".dist-info/METADATA"))
    contents[metadata] = contents[metadata].replace(
        b"Name: evoom-guard\n", b"Name: substituted-package\n", 1
    )
    _refresh_record(contents)
    tampered = tmp_path / canonical_wheel.name
    _write_canonical(tampered, contents)

    with pytest.raises(distribution.DistributionBuildError, match="METADATA Name differs"):
        distribution.audit(tampered)


def test_audit_rejects_unknown_metadata_field_with_recomputed_record(
    canonical_wheel: Path, tmp_path: Path
) -> None:
    contents = _contents(canonical_wheel)
    metadata = next(name for name in contents if name.endswith(".dist-info/METADATA"))
    contents[metadata] = contents[metadata].replace(
        b"\n\n", b"\nX-Unreviewed-Payload: accepted\n\n", 1
    )
    _refresh_record(contents)
    tampered = tmp_path / canonical_wheel.name
    _write_canonical(tampered, contents)

    with pytest.raises(
        distribution.DistributionBuildError, match="METADATA bytes or closed header fields"
    ):
        distribution.audit(tampered)


@pytest.mark.parametrize("backend_newline", [b"\n", b"\r\n"])
def test_backend_metadata_line_endings_canonicalize_to_lf(
    canonical_wheel: Path,
    tmp_path: Path,
    backend_newline: bytes,
) -> None:
    staging = tmp_path / "staging"
    version, locked = distribution._stage(ROOT, staging)
    contents = _contents(canonical_wheel)
    metadata = next(name for name in contents if name.endswith(".dist-info/METADATA"))
    expected = distribution._expected_core_metadata(staging, version)
    contents[metadata] = expected.replace(b"\n", backend_newline)
    _refresh_record(contents)
    raw_wheel = tmp_path / f"raw-{len(backend_newline)}.whl"
    _write_canonical(raw_wheel, contents)

    distribution.audit_wheel(raw_wheel, staging, locked, canonical=False)
    if backend_newline == b"\r\n":
        with pytest.raises(
            distribution.DistributionBuildError,
            match="METADATA is valid but not canonically LF-encoded",
        ):
            distribution.audit_wheel(raw_wheel, staging, locked, canonical=True)
    canonical = tmp_path / f"canonical-{len(backend_newline)}.whl"
    distribution._canonicalize(raw_wheel, canonical, staging, locked)

    canonical_contents = _contents(canonical)
    assert canonical_contents[metadata] == expected
    assert b"\r" not in canonical_contents[metadata]


def test_raw_backend_audit_rejects_mixed_metadata_line_endings(
    canonical_wheel: Path,
    tmp_path: Path,
) -> None:
    staging = tmp_path / "staging"
    _version, locked = distribution._stage(ROOT, staging)
    contents = _contents(canonical_wheel)
    metadata = next(name for name in contents if name.endswith(".dist-info/METADATA"))
    contents[metadata] = contents[metadata].replace(b"\n", b"\r\n", 1)
    _refresh_record(contents)
    raw_wheel = tmp_path / "mixed-newlines.whl"
    _write_canonical(raw_wheel, contents)

    with pytest.raises(
        distribution.DistributionBuildError,
        match="METADATA bytes or closed header fields",
    ):
        distribution.audit_wheel(raw_wheel, staging, locked, canonical=False)


def test_clean_install_disables_index_resolution_and_does_not_install_pytest(
    canonical_wheel: Path,
) -> None:
    environment = distribution._resolver_disabled_environment()
    assert environment["PIP_NO_INDEX"] == "1"
    assert environment["PIP_NO_CACHE_DIR"] == "1"
    assert environment["PIP_CONFIG_FILE"] == os.devnull
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONSAFEPATH"] == "1"
    distribution.verify(canonical_wheel)


def test_build_ignores_pythonpath_backend_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    injected = tmp_path / "injected"
    fake_backend = injected / "setuptools" / "build_meta.py"
    fake_backend.parent.mkdir(parents=True)
    (fake_backend.parent / "__init__.py").write_text("", encoding="utf-8")
    marker = tmp_path / "fake-backend-imported"
    fake_backend.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('imported', encoding='utf-8')\n"
        "raise RuntimeError('untrusted backend imported')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", str(injected))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path / "fake-home"))
    monkeypatch.setenv("PIP_TARGET", str(tmp_path / "fake-target"))
    commands: list[list[str]] = []
    real_run = distribution._run

    def capture(command: list[str], *, cwd: Path):
        commands.append(command)
        return real_run(command, cwd=cwd)

    monkeypatch.setattr(distribution, "_run", capture)
    wheel = distribution.build(tmp_path / "dist")

    assert wheel.is_file()
    assert not marker.exists()
    assert commands[0][:5] == [sys.executable, "-I", "-m", "pip", "--isolated"]
    sanitized = distribution._resolver_disabled_environment()
    assert "PYTHONPATH" not in sanitized
    assert "PYTHONHOME" not in sanitized
    assert "PIP_TARGET" not in sanitized


def test_build_backend_child_ignores_user_site_sitecustomize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / "home"
    fake_appdata = tmp_path / "appdata"
    monkeypatch.delenv("PYTHONUSERBASE", raising=False)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("APPDATA", str(fake_appdata))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-appdata"))

    user_base = site._getuserbase()
    assert user_base is not None
    user_site = Path(site._get_path(user_base))
    user_site.mkdir(parents=True)
    marker = tmp_path / "backend-child-loaded-sitecustomize"
    (user_site / "sitecustomize.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "if os.environ.get('_PYPROJECT_HOOKS_BUILD_BACKEND'):\n"
        f"    Path({str(marker)!r}).write_text('loaded', encoding='utf-8')\n",
        encoding="utf-8",
    )

    # Prove this is a live user-site hook for the same backend-child marker,
    # rather than a fixture in a directory Python would never inspect.
    probe_environment = os.environ.copy()
    probe_environment.pop("PYTHONNOUSERSITE", None)
    probe_environment.pop("PYTHONSAFEPATH", None)
    probe_environment["_PYPROJECT_HOOKS_BUILD_BACKEND"] = "setuptools.build_meta"
    probe = subprocess.run(
        [sys.executable, "-c", "pass"],
        env=probe_environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    assert marker.read_text(encoding="utf-8") == "loaded"
    marker.unlink()

    wheel = distribution.build(tmp_path / "dist")

    assert wheel.is_file()
    assert not marker.exists()
    sanitized_names = {name.upper() for name in distribution._resolver_disabled_environment()}
    for name in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"):
        assert name not in sanitized_names


def test_build_refuses_an_unlocked_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(distribution.importlib.metadata, "version", lambda _name: "0.0")
    with pytest.raises(distribution.DistributionBuildError, match="not the locked build backend"):
        distribution._require_locked_backend(ROOT)


def test_staged_build_system_matches_the_exact_locked_backend() -> None:
    locked = distribution._locked_setuptools_version(ROOT)
    distribution._validate_staged_build_system(ROOT / "pyproject.toml", locked)


@pytest.mark.parametrize(
    ("build_system", "message"),
    [
        (
            '[build-system]\nrequires = ["setuptools>=64"]\n'
            'build-backend = "setuptools.build_meta"\n',
            "exact locked requirement",
        ),
        (
            '[build-system]\nrequires = ["setuptools==83.0.0"]\n'
            'build-backend = "substituted.backend"\n',
            "exactly setuptools.build_meta",
        ),
        (
            '[build-system]\nrequires = ["setuptools==83.0.0"]\n'
            'build-backend = "setuptools.build_meta"\nbackend-path = ["backend"]\n',
            "must not define backend-path",
        ),
    ],
)
def test_staged_build_system_rejects_unbound_inputs(
    tmp_path: Path, build_system: str, message: str
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(build_system, encoding="utf-8")

    with pytest.raises(distribution.DistributionBuildError, match=message):
        distribution._validate_staged_build_system(pyproject, "83.0.0")
