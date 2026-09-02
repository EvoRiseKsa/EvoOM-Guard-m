from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from tools.packaging import build_core_wheel


def _module_path(dotted: str, *, package: bool) -> Path:
    relative = Path(*dotted.split("."))
    return relative if package else relative.with_suffix(".py")


def test_core_wheel_staging_uses_the_live_license_boundary(tmp_path: Path) -> None:
    packages, modules = build_core_wheel.platform_exclusions()

    assert "evoom_guard.admission" in packages
    assert "evoom_guard.finalizer" in packages
    assert "evoom_guard.trusted_finalizer" in modules
    assert "evoom_guard.cli.evidence_sealing_commands" in modules
    assert all(name.startswith("evoom_guard.") for name in packages | modules)

    staging = build_core_wheel.stage(tmp_path / "staging")
    assert build_core_wheel.audit(staging) >= 50
    assert (staging / "evoom_guard" / "guard.py").is_file()

    for dotted in packages:
        assert not (staging / _module_path(dotted, package=True)).exists()
    for dotted in modules:
        assert not (staging / _module_path(dotted, package=False)).exists()


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("remove_apache", "lacks the Apache SPDX header"),
        ("add_platform", "carries a source-available header"),
    ],
)
def test_core_wheel_audit_rejects_license_boundary_drift(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    staging = build_core_wheel.stage(tmp_path / mutation)
    target = staging / "evoom_guard" / "guard.py"
    text = target.read_text(encoding="utf-8")
    if mutation == "remove_apache":
        text = text.replace(build_core_wheel.APACHE_MARKER, "missing-license-marker", 1)
    else:
        text = f"# {build_core_wheel.PLATFORM_MARKER}\n{text}"
    target.write_text(text, encoding="utf-8", newline="\n")

    with pytest.raises(build_core_wheel.CoreBuildError, match=expected):
        build_core_wheel.audit(staging)


def test_core_wheel_archive_rejects_a_platform_path(tmp_path: Path) -> None:
    wheel = tmp_path / "evoom_guard_core-test.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("evoom_guard/finalizer/__init__.py", "")

    with pytest.raises(build_core_wheel.CoreBuildError, match="platform path leaked"):
        build_core_wheel.audit_wheel(wheel)
