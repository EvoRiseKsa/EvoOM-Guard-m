"""Security contracts for the judge-owned invocation receipt recorder."""

from __future__ import annotations

import os
import socket
import stat
import sys
from pathlib import Path
from types import ModuleType
from unittest import mock

import pytest

import evoom_guard.blackbox as blackbox

Recorder = blackbox._InvocationRecorder
recorder_module = sys.modules[Recorder.__module__]
assert isinstance(recorder_module, ModuleType)


def test_windows_returns_no_recorder_without_opening_a_socket(tmp_path: Path) -> None:
    with (
        mock.patch.object(recorder_module.os, "name", "nt"),
        mock.patch.object(recorder_module.socket, "socket") as socket_factory,
    ):
        assert Recorder.create(str(tmp_path)) is None
    socket_factory.assert_not_called()


def test_missing_af_unix_returns_no_recorder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(recorder_module.os, "name", "posix")
    monkeypatch.delattr(recorder_module.socket, "AF_UNIX", raising=False)
    assert Recorder.create(str(tmp_path)) is None


def test_bind_failure_closes_receiver_without_unlinking_existing_path(
    tmp_path: Path,
) -> None:
    class FailingReceiver:
        closed = False

        def bind(self, _path: str) -> None:
            raise OSError("bind rejected")

        def close(self) -> None:
            self.closed = True

    socket_path = tmp_path / ".evoguard-invocation.sock"
    socket_path.write_text("pre-existing-owner-data", encoding="utf-8")
    receiver = FailingReceiver()
    with (
        mock.patch.object(recorder_module.os, "name", "posix"),
        mock.patch.object(recorder_module.socket, "AF_UNIX", 1, create=True),
        mock.patch.object(recorder_module.socket, "socket", return_value=receiver),
    ):
        assert Recorder.create(str(tmp_path)) is None
    assert receiver.closed is True
    assert socket_path.read_text(encoding="utf-8") == "pre-existing-owner-data"


@pytest.mark.parametrize("failed_operation", ["chmod", "setblocking"])
def test_post_bind_failure_closes_and_unlinks_socket(
    tmp_path: Path, failed_operation: str
) -> None:
    class BoundReceiver:
        closed = False

        def bind(self, path: str) -> None:
            Path(path).touch()

        def setblocking(self, _enabled: bool) -> None:
            if failed_operation == "setblocking":
                raise OSError("nonblocking mode rejected")

        def close(self) -> None:
            self.closed = True

    receiver = BoundReceiver()

    def chmod_or_fail(_path: str, _mode: int) -> None:
        if failed_operation == "chmod":
            raise OSError("chmod rejected")

    socket_path = tmp_path / ".evoguard-invocation.sock"
    with (
        mock.patch.object(recorder_module.os, "name", "posix"),
        mock.patch.object(recorder_module.socket, "AF_UNIX", 1, create=True),
        mock.patch.object(recorder_module.socket, "socket", return_value=receiver),
        mock.patch.object(recorder_module.os, "chmod", side_effect=chmod_or_fail),
    ):
        assert Recorder.create(str(tmp_path)) is None
    assert receiver.closed is True
    assert not socket_path.exists()


def test_flooded_receiver_has_a_bounded_lock_hold_and_close_path() -> None:
    class EndlessReceiver:
        def __init__(self) -> None:
            self.calls = 0
            self.closed = False

        def recv(self, _size: int) -> bytes:
            self.calls += 1
            if self.calls == 1:
                return b"valid-token"
            return b"hostile-flood"

        def close(self) -> None:
            self.closed = True

    class InertReader:
        def start(self) -> None:
            pass

        def join(self, *, timeout: float) -> None:
            assert timeout == 1.0

    receiver = EndlessReceiver()
    with mock.patch.object(
        recorder_module.threading, "Thread", return_value=InertReader()
    ):
        recorder = Recorder(
            "/judge/invocation.sock", "valid-token", receiver  # type: ignore[arg-type]
        )

    limit = recorder_module._MAX_INVOCATION_DATAGRAMS_PER_DRAIN
    assert recorder.drain() == 1
    assert receiver.calls == limit
    recorder.close()
    assert receiver.calls == 2 * limit
    assert receiver.closed is True


def test_stopped_background_drain_does_not_read_an_unbounded_source() -> None:
    receiver = mock.Mock()
    receiver.recv.return_value = b"hostile-flood"
    recorder = object.__new__(Recorder)
    recorder._receiver = receiver
    recorder._receiver_lock = recorder_module.threading.Lock()
    recorder._count_lock = recorder_module.threading.Lock()
    recorder._count = 0
    recorder._token_bytes = b"valid-token"
    recorder._stop = recorder_module.threading.Event()
    recorder._stop.set()

    recorder._drain_available()
    receiver.recv.assert_not_called()


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(socket, "AF_UNIX"),
    reason="POSIX AF_UNIX datagram contract",
)
def test_valid_receipts_are_exact_cumulative_and_socket_is_owner_only(
    tmp_path: Path,
) -> None:
    recorder = Recorder.create(str(tmp_path))
    assert recorder is not None
    socket_path = Path(recorder.path)
    assert socket_path.is_socket()
    assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600

    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    closed = False
    try:
        sender.sendto(b"wrong-token", recorder.path)
        sender.sendto(recorder.token.encode("ascii"), recorder.path)
        assert recorder.drain() == 1
        assert recorder.drain() == 1

        sender.sendto(recorder.token.encode("ascii"), recorder.path)
        recorder.close()
        closed = True
        assert recorder.drain() == 2
    finally:
        sender.close()
        if not closed:
            recorder.close()
    assert not socket_path.exists()


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(socket, "AF_UNIX"),
    reason="POSIX AF_UNIX cleanup contract",
)
def test_reader_start_failure_closes_and_unlinks_socket(tmp_path: Path) -> None:
    socket_path = tmp_path / ".evoguard-invocation.sock"
    with mock.patch.object(
        recorder_module.threading.Thread,
        "start",
        side_effect=RuntimeError("thread start rejected"),
    ):
        assert Recorder.create(str(tmp_path)) is None
    assert not socket_path.exists()
