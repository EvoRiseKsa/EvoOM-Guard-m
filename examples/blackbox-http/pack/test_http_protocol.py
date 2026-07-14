"""Judge-owned HTTP protocol tests — the candidate is reached ONLY over HTTP.

The pack never imports the candidate. It launches the service across the
process boundary via $EVOGUARD_EXEC (which runs it under the delivered
isolation), waits for the port to open, asserts on the OBSERVABLE HTTP
responses, and tears the server down. In-process forgery in the candidate's
source runs inside the server process — it cannot touch this judge, and a
lying exit code changes nothing because only responses are asserted.

Boundary note: this recipe needs a judge<->candidate localhost channel, so it
runs under the SUBPROCESS black-box boundary. The hardened container modes
default to --network none, which (deliberately) severs that channel — see
docs/BLACKBOX.md for the trade-off.
"""

import json
import os
import socket
import subprocess
import time
import urllib.request

import pytest

# This pack is meaningful only when the Guard judge runs it (it sets
# EVOGUARD_EXEC and points the launcher at a candidate). Collected on its own —
# e.g. a bare `pytest examples/` — it has no candidate to launch, so skip
# rather than fail, exactly like the blackbox-cli and blackbox-pack packs. An
# all-skipped pack still FAILS under the judge (no judge-owned test results),
# so this cannot become a vacuous pass.
if not os.environ.get("EVOGUARD_EXEC"):
    pytest.skip(
        "black-box verifier pack runs only under the EvoOM Guard judge",
        allow_module_level=True,
    )


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"service never opened port {port}")


def _get_json(port: int, path: str):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


def test_add_endpoint_returns_correct_sums():
    port = _free_port()
    launcher = os.environ["EVOGUARD_EXEC"]
    python = os.environ.get("EVOGUARD_PYTHON", "python3")
    proc = subprocess.Popen(
        [launcher, python, "-m", "app", "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port(port)
        assert _get_json(port, "/add?a=2&b=3") == {"result": 5}
        assert _get_json(port, "/add?a=-1&b=1") == {"result": 0}
        assert _get_json(port, "/add?a=2.5&b=0.5") == {"result": 3}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
