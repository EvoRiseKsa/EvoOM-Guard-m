from __future__ import annotations

import json
from pathlib import Path

from evoom_guard.cli import main
from evoom_guard.pack_manifest import pack_digest

PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n"
    "-----END PUBLIC KEY-----\n"
)


def test_finalizer_cli_install_and_static_doctor(tmp_path: Path, capsys) -> None:
    root = tmp_path / "consumer"
    root.mkdir()
    key = tmp_path / "public.pem"
    key.write_text(PUBLIC_KEY, encoding="ascii")

    code = main(
        [
            "finalizer-init",
            "--root",
            str(root),
            "--public-key",
            str(key),
            "--json",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["github_controls_configured"] is False

    pack = root / "judge"
    pack.mkdir()
    (pack / "test_judge.py").write_text("def test_judge():\n    assert True\n", encoding="utf-8")
    policy = {
        "blackbox": True,
        "blackbox_only": True,
        "docker_image": "python@sha256:" + "2" * 64,
        "docker_network": "none",
        "expect_verifier_pack_sha256": pack_digest(str(pack)),
        "isolation": "docker",
        "require_candidate_isolation": "docker",
        "require_report_integrity": "external_process_isolated",
        "verifier_pack": "judge",
    }
    (root / ".evoguard.json").write_text(json.dumps(policy), encoding="utf-8")

    code = main(["finalizer-doctor", "--root", str(root), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["static_ready"] is True
    assert report["enforcement_ready"] is False


def test_finalizer_cli_no_clobber_is_an_operational_failure(tmp_path: Path, capsys) -> None:
    root = tmp_path / "consumer"
    root.mkdir()
    key = tmp_path / "public.pem"
    key.write_text(PUBLIC_KEY, encoding="ascii")
    arguments = ["finalizer-init", "--root", str(root), "--public-key", str(key)]
    assert main(arguments) == 0
    capsys.readouterr()

    assert main(arguments) == 1
    assert "refusing to overwrite" in capsys.readouterr().out
