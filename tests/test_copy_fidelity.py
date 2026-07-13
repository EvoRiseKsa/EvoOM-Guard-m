# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Throwaway-copy fidelity — symlinks, dangling links, exec bits, containment.

An external review (§10.b) flagged this exact gap: real repositories carry
symlinks (often *dangling* ones, pointing into ``.venv/`` / ``node_modules/``
that ``COPY_IGNORE`` strips) and executable scripts. Before the fix, a single
dangling symlink made ``shutil.copytree`` raise and the judge **crash with a
traceback** instead of producing a verdict. These tests pin the fixed contract:

* a dangling symlink never crashes the judge — the honest patch still gets PASS;
* symlinks are preserved *as symlinks* (no content smuggling into the copy);
* the executable bit survives the copy (suites that shell out to a script work);
* a candidate edit can never WRITE through a symlink to land outside the copy
  (neither via a symlinked file nor a symlinked parent directory).

POSIX-only where symlink creation is exercised (skipped on platforms where an
unprivileged process cannot create symlinks).
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import unittest

from evoom_guard.guard import PASS, guard
from evoom_guard.verifiers.repo_verifier import (
    apply_blocks_to_copy,
    copy_repo_tree,
)


def _can_symlink() -> bool:
    d = tempfile.mkdtemp(prefix="evo_lnk_probe_")
    try:
        os.symlink("target", os.path.join(d, "probe"))
        return True
    except (OSError, NotImplementedError):
        return False
    finally:
        shutil.rmtree(d, ignore_errors=True)


HAS_SYMLINK = _can_symlink()
HAS_PYTEST = True
try:  # the E2E cases run the real suite
    import pytest as _pytest  # noqa: F401
except ImportError:  # pragma: no cover
    HAS_PYTEST = False


def _make_repo(root: str) -> None:
    os.makedirs(os.path.join(root, "tests"), exist_ok=True)
    with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
        f.write("x = 1\n")
    with open(os.path.join(root, "tests", "test_app.py"), "w", encoding="utf-8") as f:
        f.write("import app\n\ndef test_x():\n    assert app.x == 1\n")


HONEST = "<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>"
TEST_CMD = [sys.executable, "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider"]


@unittest.skipUnless(HAS_SYMLINK, "platform cannot create symlinks")
class DanglingSymlinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_fid_")
        _make_repo(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_copy_survives_a_dangling_symlink(self) -> None:
        os.symlink("/nonexistent/target", os.path.join(self.root, "dangling"))
        dst = os.path.join(tempfile.mkdtemp(prefix="evo_fid_dst_"), "copy")
        try:
            copy_repo_tree(self.root, dst)  # must not raise
            self.assertTrue(os.path.islink(os.path.join(dst, "dangling")))
        finally:
            shutil.rmtree(os.path.dirname(dst), ignore_errors=True)

    def test_copy_survives_a_link_into_an_ignored_dir(self) -> None:
        # The common real-world shape: a link into .venv/, which COPY_IGNORE
        # strips — so the link is dangling IN THE COPY.
        os.makedirs(os.path.join(self.root, ".venv"))
        with open(os.path.join(self.root, ".venv", "cfg"), "w", encoding="utf-8") as f:
            f.write("cfg\n")
        os.symlink(
            os.path.join(self.root, ".venv", "cfg"), os.path.join(self.root, "venv_link")
        )
        dst = os.path.join(tempfile.mkdtemp(prefix="evo_fid_dst_"), "copy")
        try:
            copy_repo_tree(self.root, dst)  # must not raise
        finally:
            shutil.rmtree(os.path.dirname(dst), ignore_errors=True)

    @unittest.skipUnless(HAS_PYTEST, "pytest not installed")
    def test_guard_verdicts_instead_of_crashing_on_a_dangling_symlink(self) -> None:
        missing = os.path.join(self.root, "missing-target")
        os.symlink(missing, os.path.join(self.root, "dangling"))
        r = guard(self.root, HONEST, test_command=TEST_CMD, timeout=120)
        self.assertEqual(r.verdict, PASS, f"{r.reason}\n{r.diagnostics}")


@unittest.skipUnless(HAS_SYMLINK, "platform cannot create symlinks")
class SymlinkFidelityTests(unittest.TestCase):
    def test_symlinks_stay_symlinks_no_content_smuggling(self) -> None:
        # An absolute link to a host file must stay a LINK in the copy — its
        # target content must not be materialized into the tree (which container
        # isolation would then happily mount).
        root = tempfile.mkdtemp(prefix="evo_fid_")
        outside = tempfile.mkdtemp(prefix="evo_fid_out_")
        try:
            _make_repo(root)
            secret = os.path.join(outside, "secret.txt")
            with open(secret, "w", encoding="utf-8") as f:
                f.write("HOST-SECRET\n")
            os.symlink(secret, os.path.join(root, "link_to_host"))
            dst = os.path.join(tempfile.mkdtemp(prefix="evo_fid_dst_"), "copy")
            try:
                copy_repo_tree(root, dst)
                copied = os.path.join(dst, "link_to_host")
                self.assertTrue(os.path.islink(copied))
                # Windows may expose the same absolute target with a ``\\?\``
                # prefix. Object identity is the contract; spelling is not.
                self.assertTrue(os.path.samefile(copied, secret))
            finally:
                shutil.rmtree(os.path.dirname(dst), ignore_errors=True)
        finally:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(outside, ignore_errors=True)


@unittest.skipUnless(os.name == "posix", "exec bits are POSIX")
class ExecBitTests(unittest.TestCase):
    def test_executable_bit_survives_the_copy(self) -> None:
        root = tempfile.mkdtemp(prefix="evo_fid_")
        try:
            _make_repo(root)
            script = os.path.join(root, "run.sh")
            with open(script, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\necho ok\n")
            os.chmod(script, 0o755)
            dst = os.path.join(tempfile.mkdtemp(prefix="evo_fid_dst_"), "copy")
            try:
                copy_repo_tree(root, dst)
                mode = os.stat(os.path.join(dst, "run.sh")).st_mode
                self.assertTrue(mode & stat.S_IXUSR, "exec bit lost in the copy")
            finally:
                shutil.rmtree(os.path.dirname(dst), ignore_errors=True)
        finally:
            shutil.rmtree(root, ignore_errors=True)


@unittest.skipUnless(HAS_SYMLINK, "platform cannot create symlinks")
class SymlinkWriteContainmentTests(unittest.TestCase):
    """A candidate edit must never WRITE outside the copy through a symlink."""

    def setUp(self) -> None:
        self.copydir = tempfile.mkdtemp(prefix="evo_fid_copy_")
        self.outside = tempfile.mkdtemp(prefix="evo_fid_out_")

    def tearDown(self) -> None:
        shutil.rmtree(self.copydir, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def test_file_block_replaces_a_symlink_instead_of_writing_through_it(self) -> None:
        host_file = os.path.join(self.outside, "host.txt")
        with open(host_file, "w", encoding="utf-8") as f:
            f.write("HOST-ORIGINAL\n")
        os.symlink(host_file, os.path.join(self.copydir, "cfg"))
        err = apply_blocks_to_copy(self.copydir, {"cfg": "candidate content\n"}, [])
        self.assertIsNone(err)
        # The host file is untouched; the copy now holds a REGULAR file.
        with open(host_file, encoding="utf-8") as f:
            self.assertEqual(f.read(), "HOST-ORIGINAL\n")
        self.assertFalse(os.path.islink(os.path.join(self.copydir, "cfg")))
        with open(os.path.join(self.copydir, "cfg"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "candidate content\n")

    def test_write_through_a_symlinked_directory_is_refused(self) -> None:
        os.symlink(self.outside, os.path.join(self.copydir, "lnkdir"))
        err = apply_blocks_to_copy(
            self.copydir, {"lnkdir/evil.py": "print('escaped')\n"}, []
        )
        self.assertIsNotNone(err)
        self.assertIn("escapes the repo copy", err or "")
        self.assertEqual(os.listdir(self.outside), [])  # nothing landed outside


if __name__ == "__main__":
    unittest.main()
