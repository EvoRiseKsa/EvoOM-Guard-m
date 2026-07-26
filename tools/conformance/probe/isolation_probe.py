"""Untrusted-side isolation probe executed inside the candidate container."""

from __future__ import annotations

import json
import os
import platform
import socket
from collections.abc import Callable
from typing import Any, cast


def _write_attempt(path: str) -> dict[str, Any]:
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as exc:
        return {
            "blocked": True,
            "error": type(exc).__name__,
            "errno": exc.errno,
        }
    try:
        os.write(descriptor, b"unexpected write")
    finally:
        os.close(descriptor)
    return {"blocked": False, "error": None, "errno": None}


def _network_attempt(host: str, port: int, timeout: float) -> dict[str, Any]:
    try:
        connection = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return {
            "blocked": True,
            "error": type(exc).__name__,
            "errno": exc.errno,
        }
    connection.close()
    return {"blocked": False, "error": None, "errno": None}


def _read_attempt(path: str) -> dict[str, Any]:
    try:
        with open(path, "rb") as stream:
            sample = stream.read(64)
    except OSError as exc:
        return {
            "blocked": True,
            "error": type(exc).__name__,
            "errno": exc.errno,
            "bytes_read": 0,
        }
    return {
        "blocked": False,
        "error": None,
        "errno": None,
        "bytes_read": len(sample),
    }


def main() -> None:
    forbidden_raw = os.environ["EVOGUARD_CONFORMANCE_FORBIDDEN_PATHS"]
    forbidden_paths = json.loads(forbidden_raw)
    if not isinstance(forbidden_paths, list) or not all(
        isinstance(path, str) for path in forbidden_paths
    ):
        raise ValueError("forbidden paths must be a JSON string array")

    network_host = os.environ["EVOGUARD_CONFORMANCE_NETWORK_HOST"]
    network_port = int(os.environ["EVOGUARD_CONFORMANCE_NETWORK_PORT"])
    network_timeout = float(os.environ["EVOGUARD_CONFORMANCE_NETWORK_TIMEOUT"])
    uname = platform.uname()
    getuid = cast(Callable[[], int], os.getuid)  # type: ignore[attr-defined]
    getgid = cast(Callable[[], int], os.getgid)  # type: ignore[attr-defined]
    getgroups = cast(
        Callable[[], list[int]],
        os.getgroups,  # type: ignore[attr-defined]
    )
    result = {
        "schema_version": "evoom-isolation-probe-1",
        "identity": {
            "uid": getuid(),
            "gid": getgid(),
            "groups": getgroups(),
        },
        "kernel": {
            "system": uname.system,
            "node": uname.node,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
        },
        "attempts": {
            "candidate_mount_write": _write_attempt(
                "/candidate/EVOGUARD_CONFORMANCE_WRITE_ATTEMPT"
            ),
            "root_filesystem_write": _write_attempt(
                "/EVOGUARD_CONFORMANCE_ROOT_WRITE_ATTEMPT"
            ),
            "network_connect": {
                **_network_attempt(network_host, network_port, network_timeout),
                "host": network_host,
                "port": network_port,
            },
            "forbidden_path_read": {
                path: _read_attempt(path) for path in forbidden_paths
            },
        },
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
