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

import os
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard import __version__


def _build(tmp_path) -> str:
    # ops/ is not part of the installed package — add it on demand to import the
    # build helper (keeps the module-level import block clean).
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ops"))
    import build_pyz

    return build_pyz.build(str(tmp_path / "evo-guard.pyz"))


def test_pyz_builds_and_reports_version(tmp_path):
    out = _build(tmp_path)
    assert os.path.exists(out) and os.access(out, os.X_OK)
    r = subprocess.run([sys.executable, out, "version"], capture_output=True, text=True, timeout=90)
    assert r.returncode == 0
    assert __version__ in r.stdout


def test_pyz_build_is_byte_reproducible(tmp_path):
    first = _build(tmp_path / "first")
    second = _build(tmp_path / "second")

    with open(first, "rb") as first_file, open(second, "rb") as second_file:
        assert first_file.read() == second_file.read()

    with zipfile.ZipFile(first) as archive:
        entries = archive.infolist()
        assert [entry.filename for entry in entries] == sorted(
            entry.filename for entry in entries
        )
        assert all(entry.date_time == (1980, 1, 1, 0, 0, 0) for entry in entries)


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
