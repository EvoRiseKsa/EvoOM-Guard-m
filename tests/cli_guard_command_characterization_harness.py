"""Deterministic characterization of the public ``guard`` CLI command.

The vector freezes the command adapter before its owner is extracted.  It
records configuration/CLI precedence, all three candidate input forms,
fail-closed input handling, output/signing order, and exact process exit codes.
No repository suite or external process is started.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evoom_guard import cli  # noqa: E402
from evoom_guard import guard as guard_module  # noqa: E402
from evoom_guard import signing as signing_module  # noqa: E402
from evoom_guard.guard import ERROR, PASS, REJECTED, GuardResult  # noqa: E402
from evoom_guard.policy.config import ConfigError  # noqa: E402

SCHEMA_VERSION = "cli-guard-command-characterization-v1"
CASE_NAMES = (
    "broken_config",
    "diff_policy_defaults",
    "dirs_success",
    "dirs_unverifiable",
    "missing_input",
    "patch_cli_precedence_and_outputs",
)


def canonical_json(value: Any) -> str:
    """Return the stable human-reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _result(verdict: str, reason: str) -> GuardResult:
    return GuardResult(
        verdict=verdict,
        passed=verdict == PASS,
        reason=reason,
        files_changed=["src/app.py"],
        protected_violations=[],
        risk_level="low",
        risk_score=0.25,
        tests_passed=1 if verdict == PASS else 0,
        tests_total=1,
        verdict_source="junit+exit",
        reason_code="characterized",
    )


def _normalized(value: object, root: str) -> object:
    if isinstance(value, str):
        return value.replace(root, "<ROOT>").replace("\\", "/")
    if isinstance(value, dict):
        return {
            str(key): _normalized(item, root)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalized(item, root) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return f"<{type(value).__name__}>"


def capture_case(case_name: str) -> dict[str, Any]:
    """Capture one command result through the historical public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown CLI guard characterization case: {case_name}")

    events: list[dict[str, object]] = []
    messages: list[str] = []
    config: dict[str, object] = {
        "test_command": "policy-test && policy-finish",
        "setup_command": ["policy-setup"],
        "trust_setup_on_host": True,
        "setup_output_globs": ["generated/**"],
        "protected": ["policy/**"],
        "allow": ["policy/safe.py"],
        "timeout": 33,
        "mem_limit": 768,
        "allow_new_tests": False,
        "blackbox": False,
        "blackbox_only": False,
        "diff_coverage": False,
        "baseline_evidence": True,
        "require_demonstrated_fix": True,
        "strict_harness": True,
        "require_report_integrity": "external_process_isolated",
        "require_candidate_isolation": "subprocess",
        "min_diff_coverage": 87.5,
        "policy_id": "org/strict",
        "policy_version": "7",
        "isolation": "subprocess",
        "docker_network": "none",
    }

    with tempfile.TemporaryDirectory(prefix="cli_guard_characterization_") as root:
        repo = os.path.join(root, "repo")
        base = os.path.join(root, "base")
        head = os.path.join(root, "head")
        os.makedirs(repo)
        os.makedirs(base)
        os.makedirs(head)
        patch_path = os.path.join(root, "candidate.txt")
        diff_path = os.path.join(root, "candidate.diff")
        Path(patch_path).write_text("PATCH-BYTES", encoding="utf-8")
        Path(diff_path).write_text("DIFF-BYTES", encoding="utf-8")
        report_path = os.path.join(root, "guard.md")
        json_path = os.path.join(root, "guard.json")
        sarif_path = os.path.join(root, "guard.sarif")

        original_cli = {
            "_config_path_for_guard": cli._config_path_for_guard,
            "_load_config": cli._load_config,
            "_read_text": cli._read_text,
        }
        original_guard = {
            "blocks_from_dirs": guard_module.blocks_from_dirs,
            "guard": guard_module.guard,
            "guard_from_diff": guard_module.guard_from_diff,
            "input_error_result": guard_module.input_error_result,
            "render_report": guard_module.render_report,
            "serialize_candidate_blocks": guard_module.serialize_candidate_blocks,
            "verifier_pack_trust_error": guard_module.verifier_pack_trust_error,
            "write_json": guard_module.write_json,
            "write_sarif": guard_module.write_sarif,
        }
        original_sign = signing_module.sign_file

        def config_path(_args: object) -> str | None:
            events.append({"op": "config-path"})
            if case_name in {"diff_policy_defaults", "missing_input"}:
                return None
            if case_name == "broken_config":
                return os.path.join(root, "broken.json")
            return os.path.join(root, "trusted", ".evoguard.json")

        def load_config(
            path: str,
            *,
            required: bool = False,
            out: Callable[[str], None] = print,
        ) -> dict[str, object]:
            del out
            events.append({"op": "load-config", "path": path, "required": required})
            if case_name == "broken_config":
                raise ConfigError("controlled broken policy")
            return dict(config)

        def read_text(path: str) -> str:
            events.append({"op": "read-text", "path": path})
            return Path(path).read_text(encoding="utf-8")

        def fake_guard(repo_path: str, candidate: str, **kwargs: object) -> GuardResult:
            events.append(
                {
                    "op": "guard",
                    "repo": repo_path,
                    "candidate": candidate,
                    "kwargs": kwargs,
                }
            )
            return _result(PASS, "patch or dirs accepted")

        def fake_guard_from_diff(
            head_path: str, diff_text: str, **kwargs: object
        ) -> tuple[GuardResult, list[str]]:
            events.append(
                {
                    "op": "guard-from-diff",
                    "head": head_path,
                    "diff": diff_text,
                    "kwargs": kwargs,
                }
            )
            return _result(REJECTED, "diff rejected"), ["src/old.py"]

        def blocks_from_dirs(
            base_path: str, head_path: str
        ) -> tuple[dict[str, str], list[str]]:
            events.append(
                {"op": "blocks-from-dirs", "base": base_path, "head": head_path}
            )
            if case_name == "dirs_unverifiable":
                raise guard_module._UnverifiableChangedPathsError(
                    [("bin/app", "changed file is not valid UTF-8 text")]
                )
            return {"src/app.py": "VALUE = 2\n"}, ["src/old.py"]

        def serialize(blocks: object) -> str:
            events.append({"op": "serialize", "blocks": blocks})
            return "SERIALIZED-DIRS"

        def pack_trust(
            candidate_dir: str,
            verifier_pack: str | None,
            expected_digest: str | None,
        ) -> str | None:
            events.append(
                {
                    "op": "pack-trust",
                    "candidate": candidate_dir,
                    "pack": verifier_pack,
                    "digest": expected_digest,
                }
            )
            return None

        def input_error(reason: str, **kwargs: object) -> GuardResult:
            events.append({"op": "input-error", "reason": reason, "kwargs": kwargs})
            result = _result(ERROR, reason)
            result.source = str(kwargs["source"])
            return result

        def render(result: GuardResult, *, deleted: list[str]) -> str:
            events.append(
                {
                    "op": "render",
                    "verdict": result.verdict,
                    "deleted": deleted,
                    "source": result.source,
                }
            )
            return f"REPORT:{result.verdict}:{result.source}:{','.join(deleted)}"

        def write_json(
            result: GuardResult, path: str, *, deleted: list[str]
        ) -> None:
            events.append(
                {
                    "op": "write-json",
                    "path": path,
                    "verdict": result.verdict,
                    "deleted": deleted,
                }
            )

        def write_sarif(result: GuardResult, path: str) -> None:
            events.append(
                {"op": "write-sarif", "path": path, "verdict": result.verdict}
            )

        def sign_file(path: str, key: str) -> str:
            events.append({"op": "sign-file", "path": path, "key": key})
            return path + ".sig"

        cli._config_path_for_guard = config_path
        cli._load_config = load_config
        cli._read_text = read_text
        guard_module.blocks_from_dirs = blocks_from_dirs
        guard_module.guard = fake_guard
        guard_module.guard_from_diff = fake_guard_from_diff
        guard_module.input_error_result = input_error
        guard_module.render_report = render
        guard_module.serialize_candidate_blocks = serialize
        guard_module.verifier_pack_trust_error = pack_trust
        guard_module.write_json = write_json
        guard_module.write_sarif = write_sarif
        signing_module.sign_file = sign_file
        try:
            if case_name == "patch_cli_precedence_and_outputs":
                argv = [
                    "guard",
                    repo,
                    "--patch",
                    patch_path,
                    "--test-command",
                    "cli-test",
                    "--protected",
                    "cli/**",
                    "--allow",
                    "cli/safe.py",
                    "--allow-new-tests",
                    "--blackbox",
                    "--diff-coverage",
                    "--min-diff-coverage",
                    "91",
                    "--timeout",
                    "7",
                    "--mem-limit",
                    "256",
                    "--report",
                    report_path,
                    "--json",
                    json_path,
                    "--sarif",
                    sarif_path,
                    "--sign-key",
                    os.path.join(root, "signing.key"),
                ]
            elif case_name == "diff_policy_defaults":
                argv = ["guard", repo, "--diff", diff_path, "--no-config"]
            elif case_name in {"dirs_success", "dirs_unverifiable"}:
                argv = ["guard", "--base", base, "--head", head]
            elif case_name == "broken_config":
                argv = [
                    "guard",
                    repo,
                    "--patch",
                    patch_path,
                    "--config",
                    os.path.join(root, "broken.json"),
                ]
            else:
                argv = ["guard", "--no-config"]
            args = cli.build_parser().parse_args(argv)
            exit_code = cli.cmd_guard(args, out=messages.append)
        finally:
            cli._config_path_for_guard = original_cli["_config_path_for_guard"]
            cli._load_config = original_cli["_load_config"]
            cli._read_text = original_cli["_read_text"]
            for name, value in original_guard.items():
                setattr(guard_module, name, value)
            signing_module.sign_file = original_sign

        report_text = (
            Path(report_path).read_text(encoding="utf-8")
            if Path(report_path).exists()
            else None
        )
        return {
            "events": _normalized(events, root),
            "exit_code": exit_code,
            "messages": _normalized(messages, root),
            "report_text": report_text,
        }


def capture_all() -> dict[str, Any]:
    """Capture every reviewed command case under one versioned envelope."""

    return {
        "cases": {name: capture_case(name) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }


if __name__ == "__main__":
    print(canonical_json(capture_all()), end="")
