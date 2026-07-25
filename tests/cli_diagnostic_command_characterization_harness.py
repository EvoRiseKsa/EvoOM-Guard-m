"""Deterministic characterization of the public diagnostic CLI commands."""

from __future__ import annotations

import argparse
import json
from typing import Any

from evoom_guard import cli

SCHEMA_VERSION = "cli-diagnostic-command-characterization-v1"
CASE_NAMES = (
    "doctor_json_unsupported",
    "doctor_midcall_rebinding",
    "doctor_patch_only",
    "doctor_text_supported",
    "pack_manifest_error_report",
    "pack_midcall_rebinding",
    "pack_missing_text",
    "pack_optional_manifest_text",
    "pack_valid_json",
    "version",
)


def canonical_json(value: Any) -> str:
    """Return the stable human-reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def capture_case(case_name: str) -> dict[str, Any]:
    """Capture one command through its historical public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown diagnostic characterization case: {case_name}")

    events: list[str] = []
    messages: list[str] = []
    originals = {
        "__version__": cli.__version__,
        "digest_format": cli.PACK_DIGEST_FORMAT,
        "isdir": cli.os.path.isdir,
        "json_dumps": cli.json.dumps,
        "load_pack_manifest": cli.load_pack_manifest,
        "machine": cli.platform.machine,
        "manifest_error": cli.PackManifestError,
        "pack_digest": cli.pack_digest,
        "pack_test_files": cli.pack_test_files,
        "python_version": cli.platform.python_version,
        "sys_platform": cli.sys.platform,
        "validate_pack": cli.validate_pack,
        "which": cli.shutil.which,
    }

    cli.__version__ = "7.8.9"
    cli.sys.platform = "test-os"
    cli.platform.machine = lambda: "test-machine"
    cli.platform.python_version = lambda: "3.99.1"

    def initial_which(name: str) -> str | None:
        events.append(f"which-initial:{name}")
        if case_name == "doctor_midcall_rebinding" and name == "git":
            cli.shutil.which = late_which
            cli.platform.machine = late_machine
        if case_name == "doctor_patch_only":
            return "/trusted/patch" if name == "patch" else None
        return "/trusted/git" if name == "git" else None

    def late_which(name: str) -> str | None:
        events.append(f"which-late:{name}")
        return f"/trusted/{name}"

    def late_machine() -> str:
        events.append("machine-late")
        return "late-machine"

    cli.shutil.which = initial_which
    try:
        if case_name.startswith("doctor_"):
            if case_name == "doctor_json_unsupported":
                def missing_which(name: str) -> None:
                    events.append(f"which-missing:{name}")
                    if name == "git":
                        cli.json.dumps = late_json_dumps
                    return None

                def late_json_dumps(value: object, **kwargs: object) -> str:
                    events.append("json-dumps-late")
                    return originals["json_dumps"](value, **kwargs)

                cli.shutil.which = missing_which
            exit_code = cli.cmd_doctor(
                argparse.Namespace(
                    doctor_json=case_name == "doctor_json_unsupported"
                ),
                out=messages.append,
            )
            report = cli.doctor_report()
        elif case_name == "version":
            exit_code = cli.cmd_version(argparse.Namespace(), out=messages.append)
            report = None
        elif case_name == "pack_missing_text":
            cli.validate_pack = lambda _path: {
                "pack": "controlled-pack",
                "ok": False,
                "problems": ["not a directory"],
            }
            exit_code = cli.cmd_pack_doctor(
                argparse.Namespace(pack="controlled-pack", pack_json=False),
                out=messages.append,
            )
            report = None
        else:
            def is_directory(_path: str) -> bool:
                events.append("is-directory")
                if case_name == "pack_midcall_rebinding":
                    cli.pack_test_files = late_test_files
                    cli.load_pack_manifest = late_manifest
                    cli.pack_digest = late_digest
                    cli.PACK_DIGEST_FORMAT = "LATE_PACK_FORMAT"
                return True

            def initial_test_files(_path: str) -> list[str]:
                events.append("test-files-initial")
                return ["test_beta.py", "test_alpha.py"]

            def late_test_files(_path: str) -> list[str]:
                events.append("test-files-late")
                return ["test_late.py"]

            def initial_manifest(_path: str) -> dict[str, str] | None:
                events.append("manifest-initial")
                if case_name == "pack_optional_manifest_text":
                    return None
                if case_name == "pack_manifest_error_report":
                    class LateManifestError(ValueError):
                        pass

                    cli.PackManifestError = LateManifestError
                    raise LateManifestError("controlled manifest failure")
                return {"id": "controlled-pack", "version": "1"}

            def late_manifest(_path: str) -> dict[str, str]:
                events.append("manifest-late")
                return {"id": "late-pack", "version": "2"}

            def initial_digest(_path: str) -> str:
                events.append("digest-initial")
                if case_name == "pack_valid_json":
                    cli.json.dumps = late_json_dumps
                return "a" * 64

            def late_digest(_path: str) -> str:
                events.append("digest-late")
                return "b" * 64

            def late_json_dumps(value: object, **kwargs: object) -> str:
                events.append("json-dumps-late")
                return originals["json_dumps"](value, **kwargs)

            cli.os.path.isdir = is_directory
            cli.pack_test_files = initial_test_files
            cli.load_pack_manifest = initial_manifest
            cli.pack_digest = initial_digest
            report = cli.validate_pack("controlled-pack")
            exit_code = cli.cmd_pack_doctor(
                argparse.Namespace(
                    pack="controlled-pack",
                    pack_json=case_name == "pack_valid_json",
                ),
                out=messages.append,
            )
        return {
            "events": events,
            "exit_code": exit_code,
            "messages": messages,
            "report": report,
        }
    finally:
        cli.__version__ = originals["__version__"]
        cli.PACK_DIGEST_FORMAT = originals["digest_format"]
        cli.os.path.isdir = originals["isdir"]
        cli.json.dumps = originals["json_dumps"]
        cli.load_pack_manifest = originals["load_pack_manifest"]
        cli.platform.machine = originals["machine"]
        cli.PackManifestError = originals["manifest_error"]
        cli.pack_digest = originals["pack_digest"]
        cli.pack_test_files = originals["pack_test_files"]
        cli.platform.python_version = originals["python_version"]
        cli.sys.platform = originals["sys_platform"]
        cli.validate_pack = originals["validate_pack"]
        cli.shutil.which = originals["which"]


def capture_all() -> dict[str, Any]:
    """Capture every reviewed diagnostic case."""

    return {
        "cases": {name: capture_case(name) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }


if __name__ == "__main__":
    print(canonical_json(capture_all()), end="")
