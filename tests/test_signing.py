# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Signed verdicts (``evoom_guard/signing.py`` + the CLI surface).

The signature must be a real Ed25519 detached signature of the verdict file's
exact bytes: a valid roundtrip verifies, and ANY byte change after signing —
the attack the feature exists to catch — must flip verification to invalid.
Skipped as a module when the optional ``cryptography`` extra is absent.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

try:
    import cryptography  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - environment dependent
    HAVE_CRYPTO = False

import tempfile

from evoom_guard import cli
from evoom_guard.signing import SigningUnavailableError  # noqa: F401  (public name)


@unittest.skipUnless(HAVE_CRYPTO, "needs the 'sign' extra (cryptography)")
class SigningRoundtripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = os.path.join(self.tmp.name, "k.pem")
        self.pub = os.path.join(self.tmp.name, "k.pub")
        self.assertEqual(cli.main(["keygen", "--key", self.key, "--pub", self.pub]), 0)

    def _verdict(self, payload: dict) -> str:
        p = os.path.join(self.tmp.name, "verdict.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        return p

    def test_keygen_writes_pem_pair_and_refuses_overwrite(self) -> None:
        with open(self.key, encoding="utf-8") as f:
            self.assertIn("PRIVATE KEY", f.read())
        with open(self.pub, encoding="utf-8") as f:
            self.assertIn("PUBLIC KEY", f.read())
        # A second keygen at the same paths must not clobber the judge's identity.
        self.assertEqual(cli.main(["keygen", "--key", self.key, "--pub", self.pub]), 2)

    def test_keygen_public_collision_leaves_empty_private_reservation(self) -> None:
        from evoom_guard.signing import generate_keypair

        private = os.path.join(self.tmp.name, "collision-private.pem")
        public = os.path.join(self.tmp.name, "collision-public.pem")
        with open(public, "wb") as handle:
            handle.write(b"existing public identity")

        with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
            generate_keypair(private, public)

        self.assertTrue(os.path.isfile(private))
        self.assertEqual(os.path.getsize(private), 0)
        with open(public, "rb") as handle:
            self.assertEqual(handle.read(), b"existing public identity")

    def test_keygen_refuses_dangling_public_symlink_without_following_it(self) -> None:
        from evoom_guard.signing import generate_keypair

        private = os.path.join(self.tmp.name, "symlink-private.pem")
        public = os.path.join(self.tmp.name, "symlink-public.pem")
        target = os.path.join(self.tmp.name, "missing-target.pem")
        try:
            os.symlink(target, public)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
            generate_keypair(private, public)

        self.assertTrue(os.path.isfile(private))
        self.assertEqual(os.path.getsize(private), 0)
        self.assertTrue(os.path.islink(public))
        self.assertFalse(os.path.exists(target))

    def test_exclusive_output_fstat_failure_releases_created_descriptor(self) -> None:
        from evoom_guard import signing

        output = os.path.join(self.tmp.name, "fstat-failure.pem")
        real_open = os.open
        real_fstat = os.fstat
        created_descriptor: int | None = None

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal created_descriptor
            descriptor = real_open(path, flags, mode)
            if path == output:
                created_descriptor = descriptor
            return descriptor

        def fail_created_fstat(descriptor: int):
            if descriptor == created_descriptor:
                raise OSError("simulated output fstat failure")
            return real_fstat(descriptor)

        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(signing.os, "fstat", side_effect=fail_created_fstat),
        ):
            with self.assertRaisesRegex(OSError, "simulated output fstat failure"):
                signing._open_exclusive_key_file(output, 0o600)

        assert created_descriptor is not None
        with self.assertRaises(OSError):
            os.fstat(created_descriptor)
        self.assertTrue(os.path.isfile(output))
        self.assertEqual(os.path.getsize(output), 0)

    def test_exclusive_output_persistent_retained_close_transfers_ownership(
        self,
    ) -> None:
        from evoom_guard import signing

        output = os.path.join(self.tmp.name, "fstat-retained.pem")
        real_open = os.open
        real_close = os.close
        real_dup = os.dup
        real_fstat = os.fstat
        created_descriptor: int | None = None
        created_fstat_calls = 0
        close_attempts: list[int] = []
        owned_descriptors: set[int] = set()

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal created_descriptor
            descriptor = real_open(path, flags, mode)
            if path == output:
                created_descriptor = descriptor
                owned_descriptors.add(descriptor)
            return descriptor

        def capture_owned_dup(descriptor: int) -> int:
            duplicate = real_dup(descriptor)
            if descriptor in owned_descriptors:
                owned_descriptors.add(duplicate)
            return duplicate

        def fail_first_created_fstat(descriptor: int):
            nonlocal created_fstat_calls
            if descriptor == created_descriptor:
                created_fstat_calls += 1
                if created_fstat_calls == 1:
                    raise OSError("simulated initial output fstat failure")
            return real_fstat(descriptor)

        def persistently_fail_created_close(descriptor: int) -> None:
            if descriptor in owned_descriptors:
                close_attempts.append(descriptor)
                raise OSError("simulated persistent output close failure")
            real_close(descriptor)

        def close_owned_descriptors() -> None:
            for descriptor in owned_descriptors:
                try:
                    real_close(descriptor)
                except OSError:
                    pass

        self.addCleanup(close_owned_descriptors)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(signing.os, "dup", side_effect=capture_owned_dup),
            mock.patch.object(signing.os, "fstat", side_effect=fail_first_created_fstat),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=persistently_fail_created_close,
            ),
        ):
            with self.assertRaises(signing.OutputReservationCloseError) as raised:
                signing._open_exclusive_key_file(output, 0o600)

        self.assertEqual(
            len(close_attempts),
            signing._MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS,
        )
        self.assertEqual(len(set(close_attempts)), len(close_attempts))
        self.assertTrue(raised.exception.descriptor_retained)
        self.assertEqual(raised.exception.retained_descriptor_count, 1)
        self.assertEqual(
            raised.exception.descriptor_state,
            "indeterminate-after-close-error",
        )
        self.assertTrue(raised.exception.descriptor_ownership_indeterminate)
        self.assertTrue(raised.exception.process_exit_may_be_required)
        self.assertEqual(raised.exception.output_path, output)

        assert created_descriptor is not None
        self.assertEqual(os.fstat(created_descriptor).st_size, 0)
        self.assertTrue(raised.exception.release_retained_descriptor())
        self.assertFalse(raised.exception.descriptor_retained)

    def test_keygen_reservation_close_error_transfers_public_ownership(
        self,
    ) -> None:
        from evoom_guard import signing

        private = os.path.join(self.tmp.name, "reservation-close-private.pem")
        public = os.path.join(self.tmp.name, "reservation-close-public.pem")
        real_open = os.open
        real_close = os.close
        real_dup = os.dup
        real_fstat = os.fstat
        private_descriptor: int | None = None
        private_fstat_calls = 0
        close_attempts: list[int] = []
        owned_descriptors: set[int] = set()

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal private_descriptor
            descriptor = real_open(path, flags, mode)
            if path == private:
                private_descriptor = descriptor
                owned_descriptors.add(descriptor)
            return descriptor

        def capture_owned_dup(descriptor: int) -> int:
            duplicate = real_dup(descriptor)
            if descriptor in owned_descriptors:
                owned_descriptors.add(duplicate)
            return duplicate

        def fail_initial_private_fstat(descriptor: int):
            nonlocal private_fstat_calls
            if descriptor == private_descriptor:
                private_fstat_calls += 1
                if private_fstat_calls == 1:
                    raise OSError("simulated private reservation fstat failure")
            return real_fstat(descriptor)

        def persistently_fail_private_close(descriptor: int) -> None:
            if descriptor in owned_descriptors:
                close_attempts.append(descriptor)
                raise OSError("simulated persistent private reservation close failure")
            real_close(descriptor)

        def close_owned_descriptors() -> None:
            for descriptor in owned_descriptors:
                try:
                    real_close(descriptor)
                except OSError:
                    pass

        self.addCleanup(close_owned_descriptors)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(signing.os, "dup", side_effect=capture_owned_dup),
            mock.patch.object(
                signing.os,
                "fstat",
                side_effect=fail_initial_private_fstat,
            ),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=persistently_fail_private_close,
            ),
        ):
            with self.assertRaises(signing.KeypairCloseError) as raised:
                signing.generate_keypair(private, public)

            error = raised.exception
            self.assertIsInstance(error, OSError)
            self.assertTrue(error.descriptor_retained)
            self.assertEqual(error.retained_descriptor_count, 1)
            self.assertTrue(error.descriptor_ownership_indeterminate)
            self.assertTrue(error.process_exit_may_be_required)
            self.assertTrue(error.key_material_invalidated)
            self.assertIsInstance(error.__cause__, signing.OutputReservationCloseError)
            assert isinstance(error.__cause__, signing.OutputReservationCloseError)
            self.assertFalse(error.__cause__.descriptor_retained)
            self.assertFalse(
                error.__cause__.descriptor_ownership_indeterminate,
            )

            attempts_before_recovery = len(close_attempts)
            self.assertFalse(error.release_retained_descriptors())
            self.assertEqual(
                len(close_attempts) - attempts_before_recovery,
                signing._MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS,
            )
            self.assertTrue(error.descriptor_retained)
            self.assertEqual(error.retained_descriptor_count, 1)

        self.assertEqual(
            len(close_attempts),
            2 * signing._MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS,
        )
        self.assertEqual(len(set(close_attempts)), len(close_attempts))
        assert private_descriptor is not None
        self.assertEqual(os.fstat(private_descriptor).st_size, 0)
        self.assertTrue(raised.exception.release_retained_descriptors())
        self.assertFalse(raised.exception.descriptor_retained)

    def test_keygen_write_failure_invalidates_both_reserved_files(self) -> None:
        from evoom_guard import signing

        private = os.path.join(self.tmp.name, "write-failure-private.pem")
        public = os.path.join(self.tmp.name, "write-failure-public.pem")
        real_write_all = signing._write_all
        calls = 0

        def fail_public_write(descriptor: int, payload: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated public-key write failure")
            real_write_all(descriptor, payload)

        with mock.patch.object(signing, "_write_all", side_effect=fail_public_write):
            with self.assertRaisesRegex(OSError, "simulated public-key write failure"):
                signing.generate_keypair(private, public)

        self.assertEqual(os.path.getsize(private), 0)
        self.assertEqual(os.path.getsize(public), 0)

    def test_keygen_reports_when_key_material_invalidation_is_unproven(self) -> None:
        from evoom_guard import signing

        private = os.path.join(self.tmp.name, "unproven-private.pem")
        public = os.path.join(self.tmp.name, "unproven-public.pem")
        real_write_all = signing._write_all
        calls = 0

        def fail_after_private_write(descriptor: int, payload: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                real_write_all(descriptor, payload)
                return
            raise OSError("simulated public-key write failure")

        with (
            mock.patch.object(
                signing,
                "_write_all",
                side_effect=fail_after_private_write,
            ),
            mock.patch.object(
                signing.os,
                "ftruncate",
                side_effect=OSError("simulated invalidation failure"),
            ),
        ):
            with self.assertRaisesRegex(
                OSError,
                "key-output invalidation could not be proven",
            ):
                signing.generate_keypair(private, public)

        self.assertGreater(os.path.getsize(private), 0)
        self.assertEqual(os.path.getsize(public), 0)

    def test_keygen_close_failure_before_release_invalidates_both_outputs(
        self,
    ) -> None:
        from evoom_guard import signing

        private = os.path.join(self.tmp.name, "close-before-private.pem")
        public = os.path.join(self.tmp.name, "close-before-public.pem")
        real_close = os.close
        close_calls = 0
        failed_descriptor: int | None = None

        def fail_first_close_before_release(descriptor: int) -> None:
            nonlocal close_calls
            nonlocal failed_descriptor
            close_calls += 1
            if close_calls == 1:
                failed_descriptor = descriptor
                raise OSError("simulated close-before-release failure")
            real_close(descriptor)

        def close_failed_descriptor() -> None:
            if failed_descriptor is None:
                return
            try:
                real_close(failed_descriptor)
            except OSError:
                pass

        self.addCleanup(close_failed_descriptor)
        with mock.patch.object(
            signing.os,
            "close",
            side_effect=fail_first_close_before_release,
        ):
            with self.assertRaises(signing.KeypairCloseError) as raised:
                signing.generate_keypair(private, public)

        self.assertTrue(raised.exception.key_material_invalidated)
        self.assertFalse(raised.exception.descriptor_retained)
        self.assertTrue(raised.exception.descriptor_ownership_indeterminate)
        self.assertTrue(raised.exception.process_exit_may_be_required)
        self.assertIn("all key bytes were invalidated", str(raised.exception))
        self.assertEqual(os.path.getsize(private), 0)
        self.assertEqual(os.path.getsize(public), 0)

    def test_keygen_persistent_retained_close_is_bounded_and_recoverable(
        self,
    ) -> None:
        from evoom_guard import signing

        private = os.path.join(self.tmp.name, "persistent-close-private.pem")
        public = os.path.join(self.tmp.name, "persistent-close-public.pem")
        real_open = os.open
        real_close = os.close
        real_dup = os.dup
        private_descriptor: int | None = None
        close_attempts: list[int] = []
        owned_descriptors: set[int] = set()

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal private_descriptor
            descriptor = real_open(path, flags, mode)
            if path == private:
                private_descriptor = descriptor
                owned_descriptors.add(descriptor)
            return descriptor

        def capture_owned_dup(descriptor: int) -> int:
            duplicate = real_dup(descriptor)
            if descriptor in owned_descriptors:
                owned_descriptors.add(duplicate)
            return duplicate

        def persistently_fail_private_close(descriptor: int) -> None:
            if descriptor in owned_descriptors:
                close_attempts.append(descriptor)
                raise OSError("simulated persistent private-key close failure")
            real_close(descriptor)

        def close_owned_descriptors() -> None:
            for descriptor in owned_descriptors:
                try:
                    real_close(descriptor)
                except OSError:
                    pass

        self.addCleanup(close_owned_descriptors)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(signing.os, "dup", side_effect=capture_owned_dup),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=persistently_fail_private_close,
            ),
        ):
            with self.assertRaises(signing.KeypairCloseError) as raised:
                signing.generate_keypair(private, public)

        self.assertEqual(
            len(close_attempts),
            1 + signing._MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS,
        )
        self.assertEqual(len(set(close_attempts)), len(close_attempts))
        self.assertTrue(raised.exception.key_material_invalidated)
        self.assertTrue(raised.exception.descriptor_retained)
        self.assertEqual(raised.exception.retained_descriptor_count, 1)
        self.assertTrue(raised.exception.descriptor_ownership_indeterminate)
        self.assertTrue(raised.exception.process_exit_may_be_required)
        self.assertEqual(os.path.getsize(private), 0)
        self.assertEqual(os.path.getsize(public), 0)

        assert private_descriptor is not None
        self.assertEqual(os.fstat(private_descriptor).st_size, 0)
        with (
            mock.patch.object(
                signing.os,
                "close",
                side_effect=persistently_fail_private_close,
            ),
            mock.patch.object(signing.os, "dup", side_effect=capture_owned_dup),
        ):
            attempts_before_recovery = len(close_attempts)
            self.assertFalse(raised.exception.release_retained_descriptors())
            self.assertEqual(
                len(close_attempts) - attempts_before_recovery,
                signing._MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS,
            )
        self.assertTrue(raised.exception.release_retained_descriptors())
        self.assertFalse(raised.exception.descriptor_retained)

    @unittest.skipIf(
        os.name == "nt",
        "renaming a key path while its safe backup is open is unavailable on Windows",
    )
    def test_keygen_close_failure_after_release_never_touches_replacement(
        self,
    ) -> None:
        from evoom_guard import signing

        private = os.path.join(self.tmp.name, "close-after-private.pem")
        public = os.path.join(self.tmp.name, "close-after-public.pem")
        attacker = os.path.join(self.tmp.name, "close-after-attacker.pem")
        replacement = b"attacker-owned close replacement"
        with open(attacker, "wb") as handle:
            handle.write(replacement)
        real_close = os.close
        close_calls = 0

        def close_replace_then_raise(descriptor: int) -> None:
            nonlocal close_calls
            close_calls += 1
            real_close(descriptor)
            if close_calls == 1:
                os.replace(attacker, private)
                raise OSError("simulated close-after-release failure")

        with mock.patch.object(
            signing.os,
            "close",
            side_effect=close_replace_then_raise,
        ):
            with self.assertRaises(signing.KeypairCloseError) as raised:
                signing.generate_keypair(private, public)

        self.assertTrue(raised.exception.key_material_invalidated)
        self.assertFalse(raised.exception.descriptor_retained)
        self.assertTrue(raised.exception.descriptor_ownership_indeterminate)
        self.assertTrue(raised.exception.process_exit_may_be_required)
        self.assertIn("all key bytes were invalidated", str(raised.exception))
        with open(private, "rb") as handle:
            self.assertEqual(handle.read(), replacement)
        self.assertEqual(os.path.getsize(public), 0)

    def test_keygen_close_after_release_never_touches_same_inode_reused_fd(
        self,
    ) -> None:
        from evoom_guard import signing

        private = os.path.join(self.tmp.name, "same-inode-reuse-private.pem")
        public = os.path.join(self.tmp.name, "same-inode-reuse-public.pem")
        real_open = os.open
        real_close = os.close
        real_fstat = os.fstat
        real_ftruncate = os.ftruncate
        private_descriptor: int | None = None
        reused_descriptor: int | None = None
        reuse_installed = False
        post_reuse_close_attempts = 0
        post_reuse_fstat_attempts = 0
        post_reuse_ftruncate_attempts = 0

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal private_descriptor
            descriptor = real_open(path, flags, mode)
            if path == private:
                private_descriptor = descriptor
            return descriptor

        def close_release_reopen_same_inode_then_raise(descriptor: int) -> None:
            nonlocal reuse_installed
            nonlocal reused_descriptor
            nonlocal post_reuse_close_attempts
            if descriptor != private_descriptor:
                real_close(descriptor)
                return
            if not reuse_installed:
                real_close(descriptor)
                reopened = real_open(
                    private,
                    os.O_RDWR | getattr(os, "O_BINARY", 0),
                )
                if reopened != descriptor:
                    os.dup2(reopened, descriptor)
                    real_close(reopened)
                reused_descriptor = descriptor
                reuse_installed = True
                raise OSError("simulated close-after-release with same-inode FD reuse")
            post_reuse_close_attempts += 1
            raise OSError("cleanup attempted to close the reused descriptor")

        def record_fstat(descriptor: int):
            nonlocal post_reuse_fstat_attempts
            if reuse_installed and descriptor == private_descriptor:
                post_reuse_fstat_attempts += 1
            return real_fstat(descriptor)

        def record_ftruncate(descriptor: int, length: int) -> None:
            nonlocal post_reuse_ftruncate_attempts
            if reuse_installed and descriptor == private_descriptor:
                post_reuse_ftruncate_attempts += 1
            real_ftruncate(descriptor, length)

        def close_reused_descriptor() -> None:
            if reused_descriptor is None:
                return
            try:
                real_close(reused_descriptor)
            except OSError:
                pass

        self.addCleanup(close_reused_descriptor)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=close_release_reopen_same_inode_then_raise,
            ),
            mock.patch.object(signing.os, "fstat", side_effect=record_fstat),
            mock.patch.object(
                signing.os,
                "ftruncate",
                side_effect=record_ftruncate,
            ),
        ):
            with self.assertRaises(signing.KeypairCloseError) as raised:
                signing.generate_keypair(private, public)

        self.assertTrue(reuse_installed)
        self.assertEqual(post_reuse_close_attempts, 0)
        self.assertEqual(post_reuse_fstat_attempts, 0)
        self.assertEqual(post_reuse_ftruncate_attempts, 0)
        self.assertFalse(raised.exception.descriptor_retained)
        self.assertTrue(raised.exception.descriptor_ownership_indeterminate)
        self.assertTrue(raised.exception.process_exit_may_be_required)
        self.assertTrue(raised.exception.key_material_invalidated)
        assert reused_descriptor is not None
        self.assertEqual(
            signing._key_path_identity(real_fstat(reused_descriptor)),
            signing._key_path_identity(os.stat(private)),
        )
        self.assertEqual(os.path.getsize(private), 0)
        self.assertEqual(os.path.getsize(public), 0)

    def test_keygen_second_close_failure_cannot_claim_full_rollback(self) -> None:
        from evoom_guard import signing

        private = os.path.join(self.tmp.name, "second-close-private.pem")
        public = os.path.join(self.tmp.name, "second-close-public.pem")
        real_close = os.close
        close_calls = 0
        failed_descriptor: int | None = None

        def fail_second_close_before_release(descriptor: int) -> None:
            nonlocal close_calls
            nonlocal failed_descriptor
            close_calls += 1
            if close_calls == 2:
                failed_descriptor = descriptor
                raise OSError("simulated second close failure")
            real_close(descriptor)

        def close_failed_descriptor() -> None:
            if failed_descriptor is None:
                return
            try:
                real_close(failed_descriptor)
            except OSError:
                pass

        self.addCleanup(close_failed_descriptor)
        with mock.patch.object(
            signing.os,
            "close",
            side_effect=fail_second_close_before_release,
        ):
            with self.assertRaises(signing.KeypairCloseError) as raised:
                signing.generate_keypair(private, public)

        self.assertFalse(raised.exception.key_material_invalidated)
        self.assertFalse(raised.exception.descriptor_retained)
        self.assertTrue(raised.exception.descriptor_ownership_indeterminate)
        self.assertTrue(raised.exception.process_exit_may_be_required)
        self.assertIn("may contain committed key bytes", str(raised.exception))
        self.assertGreater(os.path.getsize(private), 0)
        self.assertEqual(os.path.getsize(public), 0)

    def test_keygen_failure_cleanup_never_deletes_a_replaced_path(self) -> None:
        from evoom_guard import signing

        private = os.path.join(self.tmp.name, "replaced-private.pem")
        public = os.path.join(self.tmp.name, "uncreated-public.pem")
        attacker = os.path.join(self.tmp.name, "attacker-owned.pem")
        with open(attacker, "wb") as handle:
            handle.write(b"attacker-owned replacement")
        real_open_exclusive = signing._open_exclusive_key_file
        reserved_private = None

        def replace_before_public(path: str, mode: int):
            nonlocal reserved_private
            if path == private:
                reserved_private = real_open_exclusive(path, mode)
                return reserved_private
            assert reserved_private is not None
            # Simulate a concurrent path replacement. Closing only models a
            # platform that permits rename while the original descriptor lives;
            # failure cleanup must perform no path-based truncate or unlink.
            signing._close_created_key_file(reserved_private)
            os.replace(attacker, private)
            raise FileExistsError("simulated public-path collision")

        with mock.patch.object(
            signing,
            "_open_exclusive_key_file",
            side_effect=replace_before_public,
        ):
            with self.assertRaisesRegex(FileExistsError, "simulated public-path collision"):
                signing.generate_keypair(private, public)

        with open(private, "rb") as handle:
            self.assertEqual(handle.read(), b"attacker-owned replacement")
        self.assertFalse(os.path.lexists(public))

    def test_keygen_fsyncs_and_rechecks_both_final_paths(self) -> None:
        from evoom_guard import signing

        private = os.path.join(self.tmp.name, "synced-private.pem")
        public = os.path.join(self.tmp.name, "synced-public.pem")
        real_fsync = os.fsync
        real_lstat = os.lstat
        fsynced: list[int] = []
        inspected: list[str] = []

        def record_fsync(descriptor: int) -> None:
            fsynced.append(descriptor)
            real_fsync(descriptor)

        def record_lstat(path: str):
            if path in {private, public}:
                inspected.append(path)
            return real_lstat(path)

        with (
            mock.patch.object(signing.os, "fsync", side_effect=record_fsync),
            mock.patch.object(signing.os, "lstat", side_effect=record_lstat),
        ):
            signing.generate_keypair(private, public)

        self.assertEqual(len(fsynced), 2)
        self.assertEqual(len(set(fsynced)), 2)
        self.assertEqual(inspected, [private, public])
        self.assertGreater(os.path.getsize(private), 0)
        self.assertGreater(os.path.getsize(public), 0)

    def _assert_keygen_same_inode_content_corruption_is_rejected(
        self,
        target_label: str,
    ) -> None:
        from evoom_guard import signing

        private = os.path.join(
            self.tmp.name,
            f"same-inode-corruption-{target_label}-private.pem",
        )
        public = os.path.join(
            self.tmp.name,
            f"same-inode-corruption-{target_label}-public.pem",
        )
        target = private if target_label == "private" else public
        real_open = os.open
        real_fstat = os.fstat
        real_fsync = os.fsync
        real_read = os.read
        real_write = os.write
        target_descriptor: int | None = None
        target_open_flags: int | None = None
        corrupted = False
        read_descriptors: list[int] = []

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal target_descriptor
            nonlocal target_open_flags
            descriptor = real_open(path, flags, mode)
            if path == target:
                target_descriptor = descriptor
                target_open_flags = flags
            return descriptor

        def corrupt_same_inode_before_validation(descriptor: int) -> None:
            nonlocal corrupted
            if descriptor == target_descriptor and not corrupted:
                size = real_fstat(descriptor).st_size
                os.lseek(descriptor, 0, os.SEEK_SET)
                replacement = b"\x00" * size
                written = 0
                while written < len(replacement):
                    written += real_write(descriptor, replacement[written:])
                corrupted = True
            real_fsync(descriptor)

        def record_read(descriptor: int, size: int) -> bytes:
            read_descriptors.append(descriptor)
            return real_read(descriptor, size)

        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(
                signing.os,
                "fsync",
                side_effect=corrupt_same_inode_before_validation,
            ),
            mock.patch.object(signing.os, "read", side_effect=record_read),
        ):
            with self.assertRaisesRegex(
                OSError,
                rf"{target_label} key content changed while it was being written",
            ):
                signing.generate_keypair(private, public)

        self.assertTrue(corrupted)
        assert target_descriptor is not None
        assert target_open_flags is not None
        self.assertEqual(
            target_open_flags & (os.O_WRONLY | os.O_RDWR),
            os.O_RDWR,
        )
        self.assertIn(target_descriptor, read_descriptors)
        self.assertEqual(os.path.getsize(private), 0)
        self.assertEqual(os.path.getsize(public), 0)

    def test_keygen_rejects_private_same_inode_content_corruption(self) -> None:
        self._assert_keygen_same_inode_content_corruption_is_rejected("private")

    def test_keygen_rejects_public_same_inode_content_corruption(self) -> None:
        self._assert_keygen_same_inode_content_corruption_is_rejected("public")

    def _assert_keygen_success_path_replacement_is_safe(
        self,
        target_label: str,
    ) -> None:
        from evoom_guard import signing

        private = os.path.join(
            self.tmp.name,
            f"success-swap-{target_label}-private.pem",
        )
        public = os.path.join(
            self.tmp.name,
            f"success-swap-{target_label}-public.pem",
        )
        target = private if target_label == "private" else public
        other = public if target_label == "private" else private
        displaced = target + ".displaced"
        replacement = b"attacker-owned success-path replacement"
        target_sync_call = 1 if target_label == "private" else 2
        sync_calls = 0
        real_fsync = os.fsync

        def replace_target_after_sync(descriptor: int) -> None:
            nonlocal sync_calls
            sync_calls += 1
            real_fsync(descriptor)
            if sync_calls != target_sync_call:
                return
            os.replace(target, displaced)
            with open(target, "wb") as handle:
                handle.write(replacement)

        with mock.patch.object(
            signing.os,
            "fsync",
            side_effect=replace_target_after_sync,
        ):
            with self.assertRaisesRegex(
                OSError,
                rf"{target_label} key path changed while it was being written",
            ):
                signing.generate_keypair(private, public)

        # Cleanup invalidates only the retained descriptors. The replacement
        # that won the pathname race must remain byte-for-byte untouched.
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(), replacement)
        self.assertEqual(os.path.getsize(displaced), 0)
        self.assertEqual(os.path.getsize(other), 0)

    @unittest.skipIf(
        os.name == "nt",
        "renaming an open key file is not portable on Windows",
    )
    def test_keygen_detects_private_success_path_replacement(self) -> None:
        self._assert_keygen_success_path_replacement_is_safe("private")

    @unittest.skipIf(
        os.name == "nt",
        "renaming an open key file is not portable on Windows",
    )
    def test_keygen_detects_public_success_path_replacement(self) -> None:
        self._assert_keygen_success_path_replacement_is_safe("public")

    def test_sign_and_verify_roundtrip(self) -> None:
        from evoom_guard.signing import sign_bytes, sign_file, verify_bytes

        p = self._verdict({"verdict": "PASS", "reason_code": "tests_passed"})
        sig = sign_file(p, self.key)
        self.assertEqual(sig, p + ".sig")
        with open(p, "rb") as f:
            payload = f.read()
        raw = sign_bytes(payload, self.key)
        self.assertEqual(len(raw), 64)
        self.assertTrue(verify_bytes(payload, raw, self.pub))
        with open(sig, "rb") as f:
            sidecar_raw = base64.b64decode(f.read().strip(), validate=True)
        self.assertTrue(verify_bytes(payload, sidecar_raw, self.pub))
        captured = io.StringIO()
        with redirect_stdout(captured):
            self.assertEqual(cli.main(["verify-verdict", p, "--pub", self.pub]), 0)
        self.assertIn(hashlib.sha256(payload).hexdigest(), captured.getvalue())

    def test_sign_file_creates_fsynced_exclusive_sidecar(self) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        real_open = os.open
        real_fsync = os.fsync
        observed_open: list[tuple[int, int]] = []
        fsynced: list[int] = []

        def record_open(path: str, flags: int, mode: int = 0o777) -> int:
            if path == sig_path:
                observed_open.append((flags, mode))
            return real_open(path, flags, mode)

        def record_fsync(descriptor: int) -> None:
            fsynced.append(descriptor)
            real_fsync(descriptor)

        with (
            mock.patch.object(signing.os, "open", side_effect=record_open),
            mock.patch.object(signing.os, "fsync", side_effect=record_fsync),
        ):
            self.assertEqual(signing.sign_file(p, self.key), sig_path)

        self.assertEqual(len(observed_open), 1)
        flags, mode = observed_open[0]
        self.assertTrue(flags & os.O_CREAT)
        self.assertTrue(flags & os.O_EXCL)
        self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR), os.O_RDWR)
        if hasattr(os, "O_NOFOLLOW"):
            self.assertTrue(flags & os.O_NOFOLLOW)
        self.assertEqual(mode, signing._SIGNATURE_SIDECAR_MODE)
        self.assertEqual(len(fsynced), 1)
        if os.name != "nt":
            self.assertEqual(os.stat(sig_path).st_mode & 0o077, 0)

    def test_sign_file_reservation_close_error_transfers_public_ownership(
        self,
    ) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        real_open = os.open
        real_close = os.close
        real_dup = os.dup
        real_fstat = os.fstat
        sidecar_descriptor: int | None = None
        sidecar_fstat_calls = 0
        close_attempts: list[int] = []
        owned_descriptors: set[int] = set()

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal sidecar_descriptor
            descriptor = real_open(path, flags, mode)
            if path == sig_path:
                sidecar_descriptor = descriptor
                owned_descriptors.add(descriptor)
            return descriptor

        def capture_owned_dup(descriptor: int) -> int:
            duplicate = real_dup(descriptor)
            if descriptor in owned_descriptors:
                owned_descriptors.add(duplicate)
            return duplicate

        def fail_initial_sidecar_fstat(descriptor: int):
            nonlocal sidecar_fstat_calls
            if descriptor == sidecar_descriptor:
                sidecar_fstat_calls += 1
                if sidecar_fstat_calls == 1:
                    raise OSError("simulated sidecar reservation fstat failure")
            return real_fstat(descriptor)

        def persistently_fail_sidecar_close(descriptor: int) -> None:
            if descriptor in owned_descriptors:
                close_attempts.append(descriptor)
                raise OSError("simulated persistent sidecar reservation close failure")
            real_close(descriptor)

        def close_owned_descriptors() -> None:
            for descriptor in owned_descriptors:
                try:
                    real_close(descriptor)
                except OSError:
                    pass

        self.addCleanup(close_owned_descriptors)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(signing.os, "dup", side_effect=capture_owned_dup),
            mock.patch.object(
                signing.os,
                "fstat",
                side_effect=fail_initial_sidecar_fstat,
            ),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=persistently_fail_sidecar_close,
            ),
        ):
            with self.assertRaises(signing.SignatureSidecarCloseError) as raised:
                signing.sign_file(p, self.key)

            error = raised.exception
            self.assertIsInstance(error, OSError)
            self.assertFalse(error.sidecar_committed)
            self.assertFalse(error.sidecar_invalidated)
            self.assertEqual(
                error.descriptor_state,
                "indeterminate-after-close-error",
            )
            self.assertTrue(error.descriptor_retained)
            self.assertEqual(error.retained_descriptor_count, 1)
            self.assertTrue(error.descriptor_ownership_indeterminate)
            self.assertTrue(error.process_exit_may_be_required)
            self.assertIsInstance(error.__cause__, signing.OutputReservationCloseError)
            assert isinstance(error.__cause__, signing.OutputReservationCloseError)
            self.assertFalse(error.__cause__.descriptor_retained)
            self.assertFalse(
                error.__cause__.descriptor_ownership_indeterminate,
            )

            attempts_before_recovery = len(close_attempts)
            self.assertFalse(error.release_retained_descriptor())
            self.assertEqual(
                len(close_attempts) - attempts_before_recovery,
                signing._MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS,
            )
            self.assertTrue(error.descriptor_retained)
            self.assertEqual(error.retained_descriptor_count, 1)

        self.assertEqual(
            len(close_attempts),
            2 * signing._MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS,
        )
        self.assertEqual(len(set(close_attempts)), len(close_attempts))
        assert sidecar_descriptor is not None
        self.assertEqual(os.fstat(sidecar_descriptor).st_size, 0)
        self.assertTrue(raised.exception.release_retained_descriptor())
        self.assertFalse(raised.exception.descriptor_retained)

    def test_sign_file_rejects_same_inode_sidecar_content_replacement(self) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        forged = base64.b64encode(b"\0" * 64) + b"\n"
        real_fsync = os.fsync
        injected = False

        def replace_exact_bytes_before_first_sync(descriptor: int) -> None:
            nonlocal injected
            if not injected:
                injected = True
                with open(sig_path, "r+b") as handle:
                    handle.write(forged)
                    handle.truncate()
            real_fsync(descriptor)

        with mock.patch.object(
            signing.os,
            "fsync",
            side_effect=replace_exact_bytes_before_first_sync,
        ):
            with self.assertRaisesRegex(
                OSError,
                "signature sidecar content changed while it was being written",
            ):
                signing.sign_file(p, self.key)

        self.assertTrue(injected)
        self.assertTrue(os.path.isfile(sig_path))
        self.assertEqual(os.path.getsize(sig_path), 0)

    def test_sign_file_retained_close_error_invalidates_and_releases_sidecar(
        self,
    ) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        real_open = os.open
        real_close = os.close
        sidecar_descriptor: int | None = None
        failed_once = False

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal sidecar_descriptor
            descriptor = real_open(path, flags, mode)
            if path == sig_path:
                sidecar_descriptor = descriptor
            return descriptor

        def fail_sidecar_close_before_release(descriptor: int) -> None:
            nonlocal failed_once
            if descriptor == sidecar_descriptor and not failed_once:
                failed_once = True
                raise OSError("simulated retained sidecar close failure")
            real_close(descriptor)

        def close_sidecar_descriptor() -> None:
            if sidecar_descriptor is None:
                return
            try:
                real_close(sidecar_descriptor)
            except OSError:
                pass

        self.addCleanup(close_sidecar_descriptor)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=fail_sidecar_close_before_release,
            ),
        ):
            with self.assertRaises(signing.SignatureSidecarCloseError) as raised:
                signing.sign_file(p, self.key)

        self.assertTrue(failed_once)
        self.assertTrue(raised.exception.sidecar_committed)
        self.assertTrue(raised.exception.sidecar_invalidated)
        self.assertEqual(
            raised.exception.descriptor_state,
            "indeterminate-after-close-error",
        )
        self.assertFalse(raised.exception.descriptor_retained)
        self.assertTrue(raised.exception.descriptor_ownership_indeterminate)
        self.assertTrue(raised.exception.process_exit_may_be_required)
        assert sidecar_descriptor is not None
        self.assertEqual(os.fstat(sidecar_descriptor).st_size, 0)
        self.assertEqual(os.path.getsize(sig_path), 0)

    def test_sign_file_persistent_retained_close_is_bounded_and_recoverable(
        self,
    ) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        real_open = os.open
        real_close = os.close
        real_dup = os.dup
        sidecar_descriptor: int | None = None
        close_attempts: list[int] = []
        owned_descriptors: set[int] = set()

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal sidecar_descriptor
            descriptor = real_open(path, flags, mode)
            if path == sig_path:
                sidecar_descriptor = descriptor
                owned_descriptors.add(descriptor)
            return descriptor

        def capture_owned_dup(descriptor: int) -> int:
            duplicate = real_dup(descriptor)
            if descriptor in owned_descriptors:
                owned_descriptors.add(duplicate)
            return duplicate

        def persistently_fail_sidecar_close(descriptor: int) -> None:
            if descriptor in owned_descriptors:
                close_attempts.append(descriptor)
                raise OSError("simulated persistent retained sidecar close failure")
            real_close(descriptor)

        def close_owned_descriptors() -> None:
            for descriptor in owned_descriptors:
                try:
                    real_close(descriptor)
                except OSError:
                    pass

        self.addCleanup(close_owned_descriptors)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(signing.os, "dup", side_effect=capture_owned_dup),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=persistently_fail_sidecar_close,
            ),
        ):
            with self.assertRaises(signing.SignatureSidecarCloseError) as raised:
                signing.sign_file(p, self.key)

        self.assertEqual(
            len(close_attempts),
            1 + signing._MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS,
        )
        self.assertEqual(len(set(close_attempts)), len(close_attempts))
        self.assertTrue(raised.exception.sidecar_committed)
        self.assertTrue(raised.exception.sidecar_invalidated)
        self.assertTrue(raised.exception.descriptor_retained)
        self.assertTrue(raised.exception.descriptor_ownership_indeterminate)
        self.assertTrue(raised.exception.process_exit_may_be_required)
        self.assertEqual(os.path.getsize(sig_path), 0)

        assert sidecar_descriptor is not None
        self.assertEqual(os.fstat(sidecar_descriptor).st_size, 0)
        with (
            mock.patch.object(
                signing.os,
                "close",
                side_effect=persistently_fail_sidecar_close,
            ),
            mock.patch.object(signing.os, "dup", side_effect=capture_owned_dup),
        ):
            attempts_before_recovery = len(close_attempts)
            self.assertFalse(raised.exception.release_retained_descriptor())
            self.assertEqual(
                len(close_attempts) - attempts_before_recovery,
                signing._MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS,
            )
        self.assertTrue(raised.exception.release_retained_descriptor())
        self.assertFalse(raised.exception.descriptor_retained)

    def test_sign_file_released_close_error_invalidates_through_safe_backup(
        self,
    ) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        real_open = os.open
        real_close = os.close
        sidecar_descriptor: int | None = None
        failed_once = False

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal sidecar_descriptor
            descriptor = real_open(path, flags, mode)
            if path == sig_path:
                sidecar_descriptor = descriptor
            return descriptor

        def fail_sidecar_close_after_release(descriptor: int) -> None:
            nonlocal failed_once
            real_close(descriptor)
            if descriptor == sidecar_descriptor and not failed_once:
                failed_once = True
                raise OSError("simulated released sidecar close failure")

        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=fail_sidecar_close_after_release,
            ),
        ):
            with self.assertRaises(signing.SignatureSidecarCloseError) as raised:
                signing.sign_file(p, self.key)

        self.assertTrue(failed_once)
        self.assertTrue(raised.exception.sidecar_committed)
        self.assertTrue(raised.exception.sidecar_invalidated)
        self.assertEqual(
            raised.exception.descriptor_state,
            "indeterminate-after-close-error",
        )
        self.assertFalse(raised.exception.descriptor_retained)
        self.assertTrue(raised.exception.descriptor_ownership_indeterminate)
        self.assertTrue(raised.exception.process_exit_may_be_required)
        self.assertEqual(os.path.getsize(sig_path), 0)

    def test_sign_file_close_after_release_never_touches_same_inode_reused_fd(
        self,
    ) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        real_open = os.open
        real_close = os.close
        real_fstat = os.fstat
        real_ftruncate = os.ftruncate
        sidecar_descriptor: int | None = None
        reused_descriptor: int | None = None
        reuse_installed = False
        post_reuse_close_attempts = 0
        post_reuse_fstat_attempts = 0
        post_reuse_ftruncate_attempts = 0

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal sidecar_descriptor
            descriptor = real_open(path, flags, mode)
            if path == sig_path:
                sidecar_descriptor = descriptor
            return descriptor

        def close_release_reopen_same_inode_then_raise(descriptor: int) -> None:
            nonlocal reuse_installed
            nonlocal reused_descriptor
            nonlocal post_reuse_close_attempts
            if descriptor != sidecar_descriptor:
                real_close(descriptor)
                return
            if not reuse_installed:
                real_close(descriptor)
                reopened = real_open(
                    sig_path,
                    os.O_RDWR | getattr(os, "O_BINARY", 0),
                )
                if reopened != descriptor:
                    os.dup2(reopened, descriptor)
                    real_close(reopened)
                reused_descriptor = descriptor
                reuse_installed = True
                raise OSError("simulated close-after-release with same-inode FD reuse")
            post_reuse_close_attempts += 1
            raise OSError("cleanup attempted to close the reused descriptor")

        def record_fstat(descriptor: int):
            nonlocal post_reuse_fstat_attempts
            if reuse_installed and descriptor == sidecar_descriptor:
                post_reuse_fstat_attempts += 1
            return real_fstat(descriptor)

        def record_ftruncate(descriptor: int, length: int) -> None:
            nonlocal post_reuse_ftruncate_attempts
            if reuse_installed and descriptor == sidecar_descriptor:
                post_reuse_ftruncate_attempts += 1
            real_ftruncate(descriptor, length)

        def close_reused_descriptor() -> None:
            if reused_descriptor is None:
                return
            try:
                real_close(reused_descriptor)
            except OSError:
                pass

        self.addCleanup(close_reused_descriptor)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=close_release_reopen_same_inode_then_raise,
            ),
            mock.patch.object(signing.os, "fstat", side_effect=record_fstat),
            mock.patch.object(
                signing.os,
                "ftruncate",
                side_effect=record_ftruncate,
            ),
        ):
            with self.assertRaises(signing.SignatureSidecarCloseError) as raised:
                signing.sign_file(p, self.key)

        self.assertTrue(reuse_installed)
        self.assertEqual(post_reuse_close_attempts, 0)
        self.assertEqual(post_reuse_fstat_attempts, 0)
        self.assertEqual(post_reuse_ftruncate_attempts, 0)
        self.assertTrue(raised.exception.sidecar_committed)
        self.assertTrue(raised.exception.sidecar_invalidated)
        self.assertEqual(
            raised.exception.descriptor_state,
            "indeterminate-after-close-error",
        )
        self.assertFalse(raised.exception.descriptor_retained)
        self.assertTrue(raised.exception.descriptor_ownership_indeterminate)
        self.assertTrue(raised.exception.process_exit_may_be_required)
        assert reused_descriptor is not None
        self.assertEqual(
            signing._key_path_identity(real_fstat(reused_descriptor)),
            signing._key_path_identity(os.stat(sig_path)),
        )
        self.assertEqual(os.path.getsize(sig_path), 0)

    def test_sign_file_refuses_existing_sidecar_without_truncating_it(self) -> None:
        from evoom_guard.signing import sign_file

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        existing = b"existing detached signature"
        with open(sig_path, "wb") as handle:
            handle.write(existing)

        with self.assertRaisesRegex(FileExistsError, "existing signature sidecar"):
            sign_file(p, self.key)

        with open(sig_path, "rb") as handle:
            self.assertEqual(handle.read(), existing)

    def test_sign_file_refuses_symlink_sidecar_without_touching_target(self) -> None:
        from evoom_guard.signing import sign_file

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        target = os.path.join(self.tmp.name, "attacker-owned.sig")
        existing = b"attacker-owned target"
        with open(target, "wb") as handle:
            handle.write(existing)
        try:
            os.symlink(target, sig_path)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(FileExistsError, "existing signature sidecar"):
            sign_file(p, self.key)

        self.assertTrue(os.path.islink(sig_path))
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(), existing)

    def test_sign_file_refuses_dangling_symlink_sidecar(self) -> None:
        from evoom_guard.signing import sign_file

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        missing_target = os.path.join(self.tmp.name, "missing-signature")
        try:
            os.symlink(missing_target, sig_path)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(FileExistsError, "existing signature sidecar"):
            sign_file(p, self.key)

        self.assertTrue(os.path.islink(sig_path))
        self.assertFalse(os.path.exists(missing_target))

    def test_sign_file_rejects_symlink_input(self) -> None:
        from evoom_guard.signing import sign_file

        p = self._verdict({"verdict": "PASS"})
        linked = os.path.join(self.tmp.name, "linked-verdict.json")
        try:
            os.symlink(p, linked)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValueError, "signed file must be a regular non-symlink"):
            sign_file(linked, self.key)
        self.assertFalse(os.path.lexists(linked + ".sig"))

    def test_verify_file_rejects_symlink_inputs(self) -> None:
        from evoom_guard.signing import sign_file, verify_file

        p = self._verdict({"verdict": "PASS"})
        sig_path = sign_file(p, self.key)
        linked_payload = os.path.join(self.tmp.name, "linked-payload.json")
        linked_signature = os.path.join(self.tmp.name, "linked-signature.sig")
        try:
            os.symlink(p, linked_payload)
            os.symlink(sig_path, linked_signature)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValueError, "signed file must be a regular non-symlink"):
            verify_file(linked_payload, sig_path, self.pub)
        with self.assertRaisesRegex(
            ValueError,
            "signature sidecar must be a regular non-symlink",
        ):
            verify_file(p, linked_signature, self.pub)

    def test_verify_file_rejects_dangling_signature_symlink(self) -> None:
        from evoom_guard.signing import verify_file

        p = self._verdict({"verdict": "PASS"})
        linked_signature = os.path.join(self.tmp.name, "dangling-signature.sig")
        missing_target = os.path.join(self.tmp.name, "missing-signature")
        try:
            os.symlink(missing_target, linked_signature)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(
            ValueError,
            "signature sidecar must be a regular non-symlink",
        ):
            verify_file(p, linked_signature, self.pub)

    def test_sign_and_verify_file_enforce_snapshot_bounds(self) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        with mock.patch.object(signing, "_MAX_SIGNED_FILE_BYTES", 3):
            with self.assertRaisesRegex(ValueError, "signed file exceeds the 3-byte limit"):
                signing.sign_file(p, self.key)
        self.assertFalse(os.path.lexists(p + ".sig"))

        sig_path = signing.sign_file(p, self.key)
        with mock.patch.object(signing, "_MAX_SIGNED_FILE_BYTES", 3):
            with self.assertRaisesRegex(ValueError, "signed file exceeds the 3-byte limit"):
                signing.verify_file(p, sig_path, self.pub)
        with mock.patch.object(signing, "_MAX_SIGNATURE_SIDECAR_BYTES", 3):
            with self.assertRaisesRegex(
                ValueError,
                "signature sidecar exceeds the 3-byte limit",
            ):
                signing.verify_file(p, sig_path, self.pub)

    def test_sign_file_rejects_input_path_change_during_snapshot(self) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        real_lstat = os.lstat
        payload_lstats = 0

        def change_second_payload_lstat(path: str):
            nonlocal payload_lstats
            current = real_lstat(path)
            if path != p:
                return current
            payload_lstats += 1
            if payload_lstats != 2:
                return current
            return SimpleNamespace(
                st_mode=current.st_mode,
                st_size=current.st_size,
                st_dev=current.st_dev,
                st_ino=current.st_ino,
                st_mtime_ns=current.st_mtime_ns + 1,
                st_ctime_ns=current.st_ctime_ns,
                st_file_attributes=getattr(current, "st_file_attributes", 0),
            )

        with mock.patch.object(signing.os, "lstat", side_effect=change_second_payload_lstat):
            with self.assertRaisesRegex(
                ValueError,
                "signed file path changed while it was being read",
            ):
                signing.sign_file(p, self.key)
        self.assertFalse(os.path.lexists(p + ".sig"))

    def test_verify_file_rejects_signature_path_change_during_snapshot(self) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        sig_path = signing.sign_file(p, self.key)
        real_lstat = os.lstat
        signature_lstats = 0

        def change_second_signature_lstat(path: str):
            nonlocal signature_lstats
            current = real_lstat(path)
            if path != sig_path:
                return current
            signature_lstats += 1
            if signature_lstats != 2:
                return current
            return SimpleNamespace(
                st_mode=current.st_mode,
                st_size=current.st_size,
                st_dev=current.st_dev,
                st_ino=current.st_ino,
                st_mtime_ns=current.st_mtime_ns + 1,
                st_ctime_ns=current.st_ctime_ns,
                st_file_attributes=getattr(current, "st_file_attributes", 0),
            )

        with mock.patch.object(
            signing.os,
            "lstat",
            side_effect=change_second_signature_lstat,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "signature sidecar path changed while it was being read",
            ):
                signing.verify_file(p, sig_path, self.pub)

    def test_sign_file_loses_creation_race_without_clobbering_winner(self) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        winner = b"concurrent winner"
        real_open = os.open
        injected = False

        def create_winner_before_exclusive_open(
            path: str,
            flags: int,
            mode: int = 0o777,
        ) -> int:
            nonlocal injected
            if path == sig_path and flags & os.O_EXCL and not injected:
                injected = True
                with open(sig_path, "wb") as handle:
                    handle.write(winner)
            return real_open(path, flags, mode)

        with mock.patch.object(
            signing.os,
            "open",
            side_effect=create_winner_before_exclusive_open,
        ):
            with self.assertRaisesRegex(FileExistsError, "existing signature sidecar"):
                signing.sign_file(p, self.key)

        with open(sig_path, "rb") as handle:
            self.assertEqual(handle.read(), winner)

    @unittest.skipIf(os.name == "nt", "renaming an open file is not portable on Windows")
    def test_sign_file_detects_post_open_sidecar_replacement(self) -> None:
        from evoom_guard import signing

        p = self._verdict({"verdict": "PASS"})
        sig_path = p + ".sig"
        moved_path = os.path.join(self.tmp.name, "original-created-sidecar")
        replacement = b"concurrent replacement"
        real_fsync = os.fsync

        def replace_path_after_sync(descriptor: int) -> None:
            real_fsync(descriptor)
            os.replace(sig_path, moved_path)
            with open(sig_path, "wb") as handle:
                handle.write(replacement)

        with mock.patch.object(
            signing.os,
            "fsync",
            side_effect=replace_path_after_sync,
        ):
            with self.assertRaisesRegex(
                OSError,
                "signature sidecar path changed while it was being written",
            ):
                signing.sign_file(p, self.key)

        with open(sig_path, "rb") as handle:
            self.assertEqual(handle.read(), replacement)
        self.assertGreater(os.path.getsize(moved_path), 0)

    def test_bytes_api_rejects_tampering_and_wrong_length(self) -> None:
        from evoom_guard.signing import sign_bytes, verify_bytes

        payload = b"exact evidence bytes\x00\xff"
        signature = sign_bytes(payload, self.key)
        corrupted = bytearray(signature)
        corrupted[-1] ^= 0x01
        self.assertFalse(verify_bytes(payload + b"!", signature, self.pub))
        self.assertFalse(verify_bytes(payload, bytes(corrupted), self.pub))
        self.assertFalse(verify_bytes(payload, signature[:-1], self.pub))

    def test_bytes_api_requires_bytes_without_implicit_coercion(self) -> None:
        from evoom_guard.signing import sign_bytes, verify_bytes

        with self.assertRaisesRegex(TypeError, "payload must be bytes"):
            sign_bytes("text", self.key)  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "payload must be bytes"):
            verify_bytes("text", b"x" * 64, self.pub)  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "signature must be bytes"):
            verify_bytes(b"payload", bytearray(64), self.pub)  # type: ignore[arg-type]

    def test_key_ids_are_sha256_of_der_spki_and_match_private_key(self) -> None:
        from cryptography.hazmat.primitives import serialization

        from evoom_guard.signing import private_key_public_id, public_key_id

        with open(self.pub, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected = "sha256:" + hashlib.sha256(der).hexdigest()
        self.assertEqual(public_key_id(self.pub), expected)
        self.assertEqual(private_key_public_id(self.key), expected)

    def test_combined_bytes_apis_bind_key_id_and_operation_to_one_load(self) -> None:
        from evoom_guard.signing import (
            sign_bytes_with_key_id,
            verify_bytes_with_key_id,
        )

        payload = b"one key snapshot"
        signature, signing_key_id = sign_bytes_with_key_id(payload, self.key)
        verified, verification_key_id = verify_bytes_with_key_id(payload, signature, self.pub)
        self.assertTrue(verified)
        self.assertEqual(signing_key_id, verification_key_id)

    def test_private_key_snapshot_rejects_oversized_file_before_parsing(self) -> None:
        from evoom_guard import signing

        oversized = os.path.join(self.tmp.name, "oversized.pem")
        with open(oversized, "wb") as handle:
            handle.write(b"x" * (signing._MAX_PRIVATE_KEY_BYTES + 1))

        with self.assertRaisesRegex(ValueError, "private key exceeds.*byte limit"):
            signing.load_signing_key_snapshot(oversized)

    def test_private_key_snapshot_rejects_symlink(self) -> None:
        from evoom_guard.signing import load_signing_key_snapshot

        linked = os.path.join(self.tmp.name, "linked-private.pem")
        try:
            os.symlink(self.key, linked)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValueError, "regular non-symlink"):
            load_signing_key_snapshot(linked)

    def test_private_key_snapshot_rejects_windows_reparse_metadata(self) -> None:
        from evoom_guard import signing

        current = os.lstat(self.key)
        reparse = SimpleNamespace(
            st_mode=current.st_mode,
            st_size=current.st_size,
            st_dev=current.st_dev,
            st_ino=current.st_ino,
            st_mtime_ns=current.st_mtime_ns,
            st_ctime_ns=current.st_ctime_ns,
            st_file_attributes=getattr(current, "st_file_attributes", 0)
            | signing.stat.FILE_ATTRIBUTE_REPARSE_POINT,
        )
        with mock.patch.object(signing.os, "lstat", return_value=reparse):
            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                signing.load_signing_key_snapshot(self.key)

    def test_private_key_snapshot_rejects_replacement_during_open(self) -> None:
        from evoom_guard import signing

        replacement = os.path.join(self.tmp.name, "replacement.pem")
        replacement_public = os.path.join(self.tmp.name, "replacement.pub")
        signing.generate_keypair(replacement, replacement_public)
        real_open = os.open
        replaced = False

        def replace_then_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal replaced
            if path == self.key and not replaced:
                os.replace(replacement, self.key)
                replaced = True
            return real_open(path, flags, mode)

        with mock.patch.object(signing.os, "open", side_effect=replace_then_open):
            with self.assertRaisesRegex(ValueError, "changed while it was being opened"):
                signing.load_signing_key_snapshot(self.key)

    def test_private_key_snapshot_rejects_descriptor_mutation_during_read(self) -> None:
        from evoom_guard import signing

        real_fstat = os.fstat
        calls = 0

        def changed_second_fstat(descriptor: int):
            nonlocal calls
            current = real_fstat(descriptor)
            calls += 1
            if calls != 2:
                return current
            return SimpleNamespace(
                st_mode=current.st_mode,
                st_size=current.st_size,
                st_dev=current.st_dev,
                st_ino=current.st_ino,
                st_mtime_ns=current.st_mtime_ns + 1,
                st_ctime_ns=current.st_ctime_ns,
                st_file_attributes=getattr(current, "st_file_attributes", 0),
            )

        with mock.patch.object(signing.os, "fstat", side_effect=changed_second_fstat):
            with self.assertRaisesRegex(ValueError, "changed while it was being read"):
                signing.load_signing_key_snapshot(self.key)

    def test_private_key_snapshot_close_failure_reports_indeterminate_ownership(
        self,
    ) -> None:
        from evoom_guard import signing

        real_open = os.open
        real_close = os.close
        key_descriptor: int | None = None
        close_attempts = 0

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal key_descriptor
            descriptor = real_open(path, flags, mode)
            if path == self.key:
                key_descriptor = descriptor
            return descriptor

        def fail_key_close_before_release(descriptor: int) -> None:
            nonlocal close_attempts
            if descriptor == key_descriptor:
                close_attempts += 1
                raise OSError("simulated input close failure before release")
            real_close(descriptor)

        def close_key_descriptor() -> None:
            if key_descriptor is None:
                return
            try:
                real_close(key_descriptor)
            except OSError:
                pass

        self.addCleanup(close_key_descriptor)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=fail_key_close_before_release,
            ),
        ):
            with self.assertRaises(signing.InputSnapshotCloseError) as raised:
                signing.load_signing_key_snapshot(self.key)

        error = raised.exception
        self.assertIsInstance(error, OSError)
        self.assertEqual(close_attempts, 1)
        self.assertEqual(error.input_path, self.key)
        self.assertEqual(
            error.descriptor_state,
            "indeterminate-after-close-error",
        )
        self.assertFalse(error.descriptor_retained)
        self.assertTrue(error.descriptor_ownership_indeterminate)
        self.assertTrue(error.process_exit_may_be_required)
        self.assertRegex(str(error), r"possible .*leak.*process exit")
        assert key_descriptor is not None
        self.assertEqual(os.fstat(key_descriptor).st_size, os.path.getsize(self.key))

    def test_private_key_snapshot_fstat_and_close_failure_preserves_ambiguity(
        self,
    ) -> None:
        from evoom_guard import signing

        real_open = os.open
        real_close = os.close
        real_fstat = os.fstat
        key_descriptor: int | None = None
        key_fstat_calls = 0
        close_attempts = 0

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal key_descriptor
            descriptor = real_open(path, flags, mode)
            if path == self.key:
                key_descriptor = descriptor
            return descriptor

        def fail_preclose_key_fstat(descriptor: int):
            nonlocal key_fstat_calls
            if descriptor == key_descriptor:
                key_fstat_calls += 1
                if key_fstat_calls == 2:
                    raise OSError("simulated pre-close input fstat failure")
            return real_fstat(descriptor)

        def fail_key_close_before_release(descriptor: int) -> None:
            nonlocal close_attempts
            if descriptor == key_descriptor:
                close_attempts += 1
                raise OSError("simulated input close failure before release")
            real_close(descriptor)

        def close_key_descriptor() -> None:
            if key_descriptor is None:
                return
            try:
                real_close(key_descriptor)
            except OSError:
                pass

        self.addCleanup(close_key_descriptor)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(
                signing.os,
                "fstat",
                side_effect=fail_preclose_key_fstat,
            ),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=fail_key_close_before_release,
            ),
        ):
            with self.assertRaises(signing.InputSnapshotCloseError) as raised:
                signing.load_signing_key_snapshot(self.key)

        error = raised.exception
        self.assertIsInstance(error, OSError)
        self.assertEqual(key_fstat_calls, 2)
        self.assertEqual(close_attempts, 1)
        self.assertEqual(error.input_path, self.key)
        self.assertEqual(
            error.descriptor_state,
            "indeterminate-after-close-error",
        )
        self.assertFalse(error.descriptor_retained)
        self.assertTrue(error.descriptor_ownership_indeterminate)
        self.assertTrue(error.process_exit_may_be_required)
        assert key_descriptor is not None
        self.assertEqual(real_fstat(key_descriptor).st_size, os.path.getsize(self.key))

    def test_private_key_snapshot_close_never_touches_same_inode_reused_fd(
        self,
    ) -> None:
        from evoom_guard import signing

        real_open = os.open
        real_close = os.close
        real_fstat = os.fstat
        real_ftruncate = os.ftruncate
        key_descriptor: int | None = None
        reused_descriptor: int | None = None
        reuse_installed = False
        post_reuse_close_attempts = 0
        post_reuse_fstat_attempts = 0
        post_reuse_ftruncate_attempts = 0

        def capture_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal key_descriptor
            descriptor = real_open(path, flags, mode)
            if path == self.key:
                key_descriptor = descriptor
            return descriptor

        def close_release_reopen_same_inode_then_raise(descriptor: int) -> None:
            nonlocal reuse_installed
            nonlocal reused_descriptor
            nonlocal post_reuse_close_attempts
            if descriptor != key_descriptor:
                real_close(descriptor)
                return
            if not reuse_installed:
                real_close(descriptor)
                reopened = real_open(
                    self.key,
                    os.O_RDONLY | getattr(os, "O_BINARY", 0),
                )
                if reopened != descriptor:
                    os.dup2(reopened, descriptor)
                    real_close(reopened)
                reused_descriptor = descriptor
                reuse_installed = True
                raise OSError("simulated input close with same-inode FD reuse")
            post_reuse_close_attempts += 1
            raise OSError("cleanup attempted to close the reused input descriptor")

        def record_fstat(descriptor: int):
            nonlocal post_reuse_fstat_attempts
            if reuse_installed and descriptor == key_descriptor:
                post_reuse_fstat_attempts += 1
            return real_fstat(descriptor)

        def record_ftruncate(descriptor: int, length: int) -> None:
            nonlocal post_reuse_ftruncate_attempts
            if reuse_installed and descriptor == key_descriptor:
                post_reuse_ftruncate_attempts += 1
            real_ftruncate(descriptor, length)

        def close_reused_descriptor() -> None:
            if reused_descriptor is None:
                return
            try:
                real_close(reused_descriptor)
            except OSError:
                pass

        self.addCleanup(close_reused_descriptor)
        with (
            mock.patch.object(signing.os, "open", side_effect=capture_open),
            mock.patch.object(
                signing.os,
                "close",
                side_effect=close_release_reopen_same_inode_then_raise,
            ),
            mock.patch.object(signing.os, "fstat", side_effect=record_fstat),
            mock.patch.object(
                signing.os,
                "ftruncate",
                side_effect=record_ftruncate,
            ),
        ):
            with self.assertRaises(signing.InputSnapshotCloseError) as raised:
                signing.load_signing_key_snapshot(self.key)

        error = raised.exception
        self.assertIsInstance(error, OSError)
        self.assertTrue(reuse_installed)
        self.assertEqual(post_reuse_close_attempts, 0)
        self.assertEqual(post_reuse_fstat_attempts, 0)
        self.assertEqual(post_reuse_ftruncate_attempts, 0)
        self.assertEqual(error.input_path, self.key)
        self.assertEqual(
            error.descriptor_state,
            "indeterminate-after-close-error",
        )
        self.assertFalse(error.descriptor_retained)
        self.assertTrue(error.descriptor_ownership_indeterminate)
        self.assertTrue(error.process_exit_may_be_required)
        assert reused_descriptor is not None
        self.assertEqual(
            signing._key_path_identity(real_fstat(reused_descriptor)),
            signing._key_path_identity(os.stat(self.key)),
        )

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "runtime has no O_NOFOLLOW")
    def test_private_key_snapshot_open_uses_no_follow(self) -> None:
        from evoom_guard import signing

        real_open = os.open
        observed_flags: list[int] = []

        def record_open(path: str, flags: int, mode: int = 0o777) -> int:
            observed_flags.append(flags)
            return real_open(path, flags, mode)

        with mock.patch.object(signing.os, "open", side_effect=record_open):
            signing.load_signing_key_snapshot(self.key)
        self.assertTrue(observed_flags)
        self.assertTrue(observed_flags[0] & os.O_NOFOLLOW)

    def test_public_key_snapshot_rejects_oversized_file_before_parsing(self) -> None:
        from evoom_guard import signing

        oversized = os.path.join(self.tmp.name, "oversized.pub")
        with open(oversized, "wb") as handle:
            handle.write(b"x" * (signing._MAX_PUBLIC_KEY_BYTES + 1))

        with self.assertRaises(ValueError) as raised:
            signing.public_key_id(oversized)
        self.assertRegex(str(raised.exception), "public key exceeds.*byte limit")
        self.assertNotIn("private key", str(raised.exception))

    def test_public_key_snapshot_rejects_symlink(self) -> None:
        from evoom_guard.signing import public_key_id

        linked = os.path.join(self.tmp.name, "linked-public.pem")
        try:
            os.symlink(self.pub, linked)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValueError, "public key must be a regular non-symlink"):
            public_key_id(linked)

    def test_public_key_snapshot_rejects_windows_reparse_metadata(self) -> None:
        from evoom_guard import signing

        current = os.lstat(self.pub)
        reparse = SimpleNamespace(
            st_mode=current.st_mode,
            st_size=current.st_size,
            st_dev=current.st_dev,
            st_ino=current.st_ino,
            st_mtime_ns=current.st_mtime_ns,
            st_ctime_ns=current.st_ctime_ns,
            st_file_attributes=getattr(current, "st_file_attributes", 0)
            | signing.stat.FILE_ATTRIBUTE_REPARSE_POINT,
        )
        with mock.patch.object(signing.os, "lstat", return_value=reparse):
            with self.assertRaisesRegex(ValueError, "public key must be a regular non-symlink"):
                signing.public_key_id(self.pub)

    def test_public_key_snapshot_rejects_replacement_during_open(self) -> None:
        from evoom_guard import signing

        replacement = os.path.join(self.tmp.name, "replacement-public-private.pem")
        replacement_public = os.path.join(self.tmp.name, "replacement-public.pub")
        signing.generate_keypair(replacement, replacement_public)
        real_open = os.open
        replaced = False

        def replace_then_open(path: str, flags: int, mode: int = 0o777) -> int:
            nonlocal replaced
            if path == self.pub and not replaced:
                os.replace(replacement_public, self.pub)
                replaced = True
            return real_open(path, flags, mode)

        with mock.patch.object(signing.os, "open", side_effect=replace_then_open):
            with self.assertRaisesRegex(ValueError, "public key changed while it was being opened"):
                signing.public_key_id(self.pub)

    def test_public_key_snapshot_rejects_descriptor_mutation_during_read(self) -> None:
        from evoom_guard import signing

        real_fstat = os.fstat
        calls = 0

        def changed_second_fstat(descriptor: int):
            nonlocal calls
            current = real_fstat(descriptor)
            calls += 1
            if calls != 2:
                return current
            return SimpleNamespace(
                st_mode=current.st_mode,
                st_size=current.st_size,
                st_dev=current.st_dev,
                st_ino=current.st_ino,
                st_mtime_ns=current.st_mtime_ns + 1,
                st_ctime_ns=current.st_ctime_ns,
                st_file_attributes=getattr(current, "st_file_attributes", 0),
            )

        with mock.patch.object(signing.os, "fstat", side_effect=changed_second_fstat):
            with self.assertRaisesRegex(ValueError, "public key changed while it was being read"):
                signing.public_key_id(self.pub)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "runtime has no O_NOFOLLOW")
    def test_public_key_snapshot_open_uses_no_follow(self) -> None:
        from evoom_guard import signing

        real_open = os.open
        observed_flags: list[int] = []

        def record_open(path: str, flags: int, mode: int = 0o777) -> int:
            observed_flags.append(flags)
            return real_open(path, flags, mode)

        with mock.patch.object(signing.os, "open", side_effect=record_open):
            signing.public_key_id(self.pub)
        self.assertTrue(observed_flags)
        self.assertTrue(observed_flags[0] & os.O_NOFOLLOW)

    def test_malformed_or_non_ed25519_keys_raise_clear_errors(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from evoom_guard.signing import (
            private_key_public_id,
            public_key_id,
            sign_bytes,
            verify_bytes,
        )

        malformed = os.path.join(self.tmp.name, "malformed.pem")
        with open(malformed, "wb") as f:
            f.write(b"not a PEM key")
        with self.assertRaisesRegex(ValueError, "unable to load.*PEM private key"):
            sign_bytes(b"payload", malformed)
        with self.assertRaisesRegex(ValueError, "unable to load a PEM public key"):
            verify_bytes(b"payload", b"x" * 64, malformed)

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_private = os.path.join(self.tmp.name, "rsa-private.pem")
        rsa_public = os.path.join(self.tmp.name, "rsa-public.pem")
        with open(rsa_private, "wb") as f:
            f.write(
                rsa_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(rsa_public, "wb") as f:
            f.write(
                rsa_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        with self.assertRaisesRegex(ValueError, "not an Ed25519 private key"):
            private_key_public_id(rsa_private)
        with self.assertRaisesRegex(ValueError, "not an Ed25519 public key"):
            public_key_id(rsa_public)

    def test_tampered_verdict_is_invalid(self) -> None:
        from evoom_guard.signing import sign_file

        p = self._verdict({"verdict": "FAIL", "reason_code": "tests_failed"})
        sign_file(p, self.key)
        # The attack: upgrade FAIL to PASS after the judge signed.
        with open(p, encoding="utf-8") as f:
            forged = f.read().replace("FAIL", "PASS")
        with open(p, "w", encoding="utf-8") as f:
            f.write(forged)
        self.assertEqual(cli.main(["verify-verdict", p, "--pub", self.pub]), 1)

    def test_tampered_signature_is_invalid_or_unusable(self) -> None:
        from evoom_guard.signing import sign_file

        p = self._verdict({"verdict": "PASS"})
        sig = sign_file(p, self.key)
        with open(sig, "rb") as f:
            raw = bytearray(f.read())
        raw[0] ^= 0x01  # corrupt the base64 head
        with open(sig, "wb") as f:
            f.write(raw)
        self.assertIn(cli.main(["verify-verdict", p, "--pub", self.pub]), (1, 2))

    def test_wrong_key_is_invalid(self) -> None:
        from evoom_guard.signing import sign_file

        p = self._verdict({"verdict": "PASS"})
        sign_file(p, self.key)
        other_key = os.path.join(self.tmp.name, "other.pem")
        other_pub = os.path.join(self.tmp.name, "other.pub")
        self.assertEqual(cli.main(["keygen", "--key", other_key, "--pub", other_pub]), 0)
        self.assertEqual(cli.main(["verify-verdict", p, "--pub", other_pub]), 1)

    def test_guard_sign_key_signs_the_json_verdict(self) -> None:
        # A REJECTED run still signs: the signature covers the verdict, whatever it is.
        repo = os.path.join(self.tmp.name, "repo")
        os.makedirs(os.path.join(repo, "tests"))
        with open(os.path.join(repo, "tests", "test_x.py"), "w", encoding="utf-8") as f:
            f.write("def test_x():\n    assert True\n")
        patch = os.path.join(self.tmp.name, "cheat.txt")
        with open(patch, "w", encoding="utf-8") as f:
            f.write("<<<FILE: tests/test_x.py>>>\ndef test_x():\n    assert True\n<<<END FILE>>>\n")
        jout = os.path.join(self.tmp.name, "out.json")
        rc = cli.main(
            [
                "guard",
                repo,
                "--patch",
                patch,
                "--json",
                jout,
                "--sign-key",
                self.key,
                "--acknowledge-local-key-exposure",
                "--report",
                os.path.join(self.tmp.name, "r.md"),
            ]
        )
        self.assertEqual(rc, 1)  # REJECTED
        self.assertTrue(os.path.exists(jout + ".sig"))
        self.assertEqual(cli.main(["verify-verdict", jout, "--pub", self.pub]), 0)


class SignKeyUsageTests(unittest.TestCase):
    def test_sign_key_without_json_is_a_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            os.makedirs(repo)
            patch = os.path.join(tmp, "p.txt")
            with open(patch, "w", encoding="utf-8") as f:
                f.write("<<<FILE: a.py>>>\nx = 1\n<<<END FILE>>>\n")
            rc = cli.main(
                [
                    "guard",
                    repo,
                    "--patch",
                    patch,
                    "--sign-key",
                    "nonexistent.pem",
                    "--report",
                    os.path.join(tmp, "r.md"),
                ]
            )
            self.assertEqual(rc, 2)

    def test_sign_key_requires_explicit_trusted_local_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            os.makedirs(repo)
            patch = os.path.join(tmp, "p.txt")
            verdict = os.path.join(tmp, "verdict.json")
            report = os.path.join(tmp, "report.md")
            with open(patch, "w", encoding="utf-8") as f:
                f.write("<<<FILE: a.py>>>\nx = 1\n<<<END FILE>>>\n")
            rc = cli.main(
                [
                    "guard",
                    repo,
                    "--patch",
                    patch,
                    "--json",
                    verdict,
                    "--sign-key",
                    "must-not-be-opened.pem",
                    "--report",
                    report,
                ]
            )
            self.assertEqual(rc, 2)
            self.assertFalse(os.path.exists(verdict))
            self.assertFalse(os.path.exists(report))


if __name__ == "__main__":
    unittest.main()
