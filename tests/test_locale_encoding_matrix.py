# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Locale/encoding matrix for the judge's verdict path.

The v3.5.1 fix made the judge read runner pipes as UTF-8 with replacement,
independent of the host code page. Decoding is only one of the surfaces a
locale touches, though: the report that motivated this work also named the
child's own output-encoding default, non-ASCII filenames, and non-ASCII
environment-variable values. These parametrized tests pin the invariant
across all of them:

  the verdict is decided by the judge-owned JUnit oracle (or exit code), so
  it is the SAME under every locale — and no locale ever turns a decode into
  a crash instead of a verdict.

Each case forces the *candidate's* process locale via PYTHONIOENCODING /
PYTHONUTF8 / PYTHONLEGACYWINDOWSSTDIO; the judge process is untouched.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.guard import FAIL, PASS, guard  # noqa: E402

# (label, child-process env overrides). cp1252 is the historical Windows-1252
# default that broke the raw-UTF-8 banner; cp1256 is the Arabic code page on
# the primary development machine; utf-8 is the modern default; the legacy flag
# forces the pre-PEP-528 Windows console codec path.
_LOCALES = (
    ("utf-8", {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}),
    ("cp1252", {"PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}),
    ("cp1256", {"PYTHONIOENCODING": "cp1256", "PYTHONUTF8": "0"}),
    ("ascii", {"PYTHONIOENCODING": "ascii", "PYTHONUTF8": "0"}),
    (
        "legacy-windows",
        {"PYTHONUTF8": "0", "PYTHONLEGACYWINDOWSSTDIO": "1"},
    ),
)

# A mix that no single legacy code page can encode: accented Latin (cp1252),
# Arabic (cp1256), CJK, and an astral emoji. Whatever the child locale, the
# judge must survive reading it.
_WIDE_TEXT = "café ❯ مرحبا 世界 \U0001f600"


def _wrapper(inner_command: list[str], overrides: dict[str, str]) -> list[str]:
    # A tiny launcher that re-execs the real runner with the locale overrides
    # applied to the child only — the judge's own process keeps its environment.
    setenv = "; ".join(f"os.environ[{k!r}]={v!r}" for k, v in overrides.items())
    prog = (
        "import os, sys, subprocess; "
        f"{setenv}; "
        "sys.exit(subprocess.run([sys.executable, *sys.argv[1:]], "
        "env=os.environ).returncode)"
    )
    return [sys.executable, "-c", prog, *inner_command[1:]]


class LocaleEncodingMatrixTests(unittest.TestCase):
    def _repo(self) -> str:
        import tempfile

        root = tempfile.mkdtemp(prefix="evo_locale_")
        os.makedirs(os.path.join(root, "pkg"))
        os.makedirs(os.path.join(root, "tests"))
        open(os.path.join(root, "pkg", "__init__.py"), "w").close()
        with open(os.path.join(root, "pkg", "m.py"), "w", encoding="utf-8") as f:
            f.write("def dbl(x):\n    return x + x + 1\n")  # bug
        with open(
            os.path.join(root, "tests", "test_m.py"), "w", encoding="utf-8"
        ) as f:
            f.write("from pkg.m import dbl\n\n\ndef test_dbl():\n    assert dbl(3) == 6\n")
        self.addCleanup(_rmtree, root)
        return root

    def test_pytest_verdict_is_identical_across_the_locale_matrix(self) -> None:
        """The JUnit-graded verdict of the same fix is locale-invariant."""
        fix = "<<<FILE: pkg/m.py>>>\ndef dbl(x):\n    return x * 2\n<<<END FILE>>>"
        pytest_cmd = [sys.executable, "-m", "pytest", "-q"]
        for label, overrides in _LOCALES:
            with self.subTest(locale=label):
                root = self._repo()
                r = guard(
                    root, fix,
                    test_command=_wrapper(pytest_cmd, overrides),
                    mem_limit_mb=0,
                )
                self.assertEqual(r.verdict, PASS, f"{label}: {r.reason}")
                self.assertEqual((r.tests_passed, r.tests_total), (1, 1))
                self.assertEqual(r.verdict_source, "junit+exit")

    def test_wide_runner_output_never_crashes_the_judge(self) -> None:
        """A runner emitting un-encodable-for-the-locale text still yields FAIL.

        The regressive crash it guards (``text=True`` decoding a runner pipe
        with ``locale.getpreferredencoding()``) reproduces only on a host whose
        ANSI code page has undefined byte slots — cp1252, i.e. the CI Windows
        smoke job, not a cp1256 machine where every byte decodes to mojibake.
        The verdict-invariance and no-exception assertions here bite on every
        host regardless.
        """
        for label, overrides in _LOCALES:
            with self.subTest(locale=label):
                root = self._repo()
                runner = os.path.join(root, "runner.py")
                with open(runner, "w", encoding="utf-8") as f:
                    f.write(
                        "import sys\n"
                        f"sys.stdout.buffer.write({_WIDE_TEXT!r}.encode('utf-8'))\n"
                        "sys.stdout.buffer.write(b'\\n')\n"
                        "sys.exit(1)\n"
                    )
                wrong = "<<<FILE: pkg/m.py>>>\ndef dbl(x):\n    return x * 3\n<<<END FILE>>>"
                r = guard(
                    root, wrong,
                    test_command=_wrapper([sys.executable, runner], overrides),
                    mem_limit_mb=0,
                )
                # No JUnit report from a bare runner -> verdict from exit code.
                self.assertEqual(r.verdict, FAIL, f"{label}: {r.reason}")
                self.assertFalse(r.passed)
                self.assertIsInstance(r.diagnostics, str)

    def test_non_ascii_candidate_filename_grades_correctly(self) -> None:
        """A new source file with a non-ASCII name is applied and graded."""
        root = self._repo()
        # The fix, plus a helper module whose name no legacy code page shares.
        candidate = (
            "<<<FILE: pkg/m.py>>>\n"
            "from pkg.é世 import factor\n\n"
            "def dbl(x):\n    return x * factor()\n"
            "<<<END FILE>>>\n"
            "<<<FILE: pkg/é世.py>>>\n"
            "def factor():\n    return 2\n"
            "<<<END FILE>>>"
        )
        r = guard(
            root, candidate,
            test_command=[sys.executable, "-m", "pytest", "-q"],
            mem_limit_mb=0,
        )
        self.assertEqual(r.verdict, PASS, r.reason)
        self.assertEqual((r.tests_passed, r.tests_total), (1, 1))


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
