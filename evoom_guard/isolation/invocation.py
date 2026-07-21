"""Judge-owned transport for candidate-launcher invocation receipts.

This module records runtime facts only. It does not decide whether a receipt is
sufficient for an isolation claim; black-box verdict composition retains that
policy, including the additional CID requirement for container modes.
"""

from __future__ import annotations

import os
import secrets
import socket
import threading

_MAX_INVOCATION_DATAGRAMS_PER_DRAIN = 256


def _discard_invocation_receiver(
    receiver: socket.socket, path: str, *, bound: bool
) -> None:
    """Best-effort cleanup for a recorder that failed during construction."""

    try:
        receiver.close()
    except OSError:
        pass
    if bound:
        try:
            os.unlink(path)
        except OSError:
            pass


class InvocationRecorder:
    """Judge-owned, one-way receipts proving that EVOGUARD_EXEC was invoked.

    The random token lives in the launcher sidecar outside the candidate tree
    and is not exported through the candidate environment.  The launcher sends
    it over a POSIX datagram socket *before* exec.  Once queued in the judge's
    socket buffer, candidate code cannot erase that first receipt.  A candidate
    may discover the token after it has started, but by then the fact we need to
    prove -- at least one real launcher invocation -- has already occurred.
    """

    def __init__(self, path: str, token: str, receiver: socket.socket) -> None:
        self.path = path
        self.token = token
        self._token_bytes = token.encode("ascii")
        self._receiver = receiver
        self._count = 0
        self._receiver_lock = threading.Lock()
        self._count_lock = threading.Lock()
        self._stop = threading.Event()
        # Drain continuously: Linux's AF_UNIX datagram queue is deliberately
        # small on many hosts. Waiting until pytest exits could block the 11th
        # or later concurrent launcher and deadlock an otherwise valid pack.
        self._reader = threading.Thread(
            target=self._read_loop,
            name="evoguard-invocation-recorder",
            daemon=True,
        )
        self._reader.start()

    @classmethod
    def create(cls, workdir: str) -> InvocationRecorder | None:
        # Native Windows black-box execution already fails closed, and not all
        # Python/socket builds expose AF_UNIX.  In either case, no receipt is
        # strictly safer than asserting evidence that was not observed.
        if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
            return None
        path = os.path.join(workdir, ".evoguard-invocation.sock")
        receiver: socket.socket | None = None
        bound = False
        try:
            receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            receiver.bind(path)
            bound = True
            os.chmod(path, 0o600)
            receiver.setblocking(False)
        except OSError:
            if receiver is not None:
                _discard_invocation_receiver(receiver, path, bound=bound)
            return None
        try:
            return cls(path, secrets.token_hex(32), receiver)
        except (OSError, RuntimeError):
            _discard_invocation_receiver(receiver, path, bound=True)
            return None

    def drain(self) -> int:
        """Drain queued datagrams and return the cumulative valid receipt count."""
        self._drain_available()
        with self._count_lock:
            return self._count

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            self._drain_available()
            self._stop.wait(0.01)

    def _drain_available(self, *, final: bool = False) -> None:
        valid = 0
        with self._receiver_lock:
            # A same-UID host candidate can locate and flood the socket. Bound
            # each lock hold so invalid traffic cannot starve drain()/close().
            for _ in range(_MAX_INVOCATION_DATAGRAMS_PER_DRAIN):
                if self._stop.is_set() and not final:
                    break
                try:
                    payload = self._receiver.recv(4096)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                if payload == self._token_bytes:
                    valid += 1
            # Publish the count before releasing the receive lock. Otherwise a
            # result-building thread could drain an empty queue and read the old
            # count in the tiny gap after the reader consumed the datagram.
            if valid:
                with self._count_lock:
                    self._count += valid

    def close(self) -> None:
        self._stop.set()
        self._reader.join(timeout=1.0)
        # One final synchronous drain closes the small race between the last
        # sender and the reader observing the stop event. The final batch is
        # still bounded, so a hostile flood cannot hold cleanup indefinitely.
        self._drain_available(final=True)
        try:
            self._receiver.close()
        finally:
            try:
                os.unlink(self.path)
            except OSError:
                pass
