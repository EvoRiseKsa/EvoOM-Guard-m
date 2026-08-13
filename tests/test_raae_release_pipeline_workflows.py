# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Static trust-boundary contracts for the inert A-H release pipeline."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from evoom_guard.pack_manifest import pack_digest
from evoom_guard.signing import public_key_id
from evoom_guard.verifiers.candidate_preflight import (
    CandidatePreflightRequest,
    evaluate_candidate_preflight,
)
from tools.ci import validate_release_candidate_scope as candidate_scope

ROOT = Path(__file__).parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

A = WORKFLOWS / "evoguard-release-source-reverify.yml"
B = WORKFLOWS / "evoguard-produce-release-source-receipt.yml"
C = WORKFLOWS / "evoguard-admit-release-source.yml"
E = WORKFLOWS / "evoguard-build-release-artifact.yml"
F = WORKFLOWS / "evoguard-admit-release-artifact.yml"
G = WORKFLOWS / "evoguard-verify-release-artifact.yml"
H = WORKFLOWS / "evoguard-publish-admitted-release.yml"
LEGACY = WORKFLOWS / "release.yml"

PINNED_GH_VERSION = "2.97.0"
PINNED_GH_ARCHIVE_SHA256 = (
    "a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112"
)
PINNED_GH_ARCHIVE_SIZE = "14770812"
PINNED_GH_EXECUTABLE = "/opt/evoguard-tools/gh-2.97.0/bin/gh"
PINNED_GH_EXECUTABLE_SHA256 = (
    "141507c337e8b202ad398550c3b73d72f5af92e86f71665214538a81efd4c409"
)
PINNED_GH_EXECUTABLE_SIZE = "40992930"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _job(path: Path, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        _text(path),
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"missing job {path.name}:{name}"
    return match.group(0)


def _literal_run_blocks(path: Path) -> list[str]:
    """Return YAML literal run scalars without adding a YAML test dependency."""

    lines = _text(path).splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(?P<indent> +)run:\s+\|\s*$", lines[index])
        if match is None:
            index += 1
            continue
        parent_indent = len(match.group("indent"))
        end = index + 1
        raw: list[str] = []
        while end < len(lines):
            line = lines[end]
            indentation = len(line) - len(line.lstrip(" "))
            if line.strip() and indentation <= parent_indent:
                break
            raw.append(line)
            end += 1
        content_indents = [
            len(line) - len(line.lstrip(" ")) for line in raw if line.strip()
        ]
        assert content_indents, f"empty literal run block in {path.name}"
        content_indent = min(content_indents)
        blocks.append(
            "\n".join(
                line[content_indent:] if line.strip() else ""
                for line in raw
            )
        )
        index = end
    return blocks


def _python_heredocs(path: Path) -> list[str]:
    """Extract the exact Python sources embedded in literal workflow steps."""

    sources: list[str] = []
    for block_index, run in enumerate(_literal_run_blocks(path)):
        lines = run.splitlines()
        index = 0
        while index < len(lines):
            if "<<'PY'" not in lines[index]:
                index += 1
                continue
            end = index + 1
            source: list[str] = []
            while end < len(lines) and lines[end] != "PY":
                source.append(lines[end])
                end += 1
            assert end < len(lines), (
                f"unclosed Python heredoc in {path.name} run block {block_index}"
            )
            sources.append("\n".join(source) + "\n")
            index = end + 1
    return sources


def _gh_materialization_blocks(path: Path) -> list[str]:
    return [
        run
        for run in _literal_run_blocks(path)
        if 'archive="$RUNNER_TEMP/gh_${EVOGUARD_PINNED_GH_VERSION}' in run
    ]


def _working_bash() -> str | None:
    """Return a Bash executable that can run workflow control-flow tests."""

    candidates: list[Path] = []
    discovered = shutil.which("bash")
    if discovered:
        candidates.append(Path(discovered))
    git = shutil.which("git")
    if os.name == "nt" and git:
        git_root = Path(git).resolve().parents[1]
        candidates.extend(
            (git_root / "bin" / "bash.exe", git_root / "usr" / "bin" / "bash.exe")
        )
    for candidate in dict.fromkeys(candidates):
        try:
            probe = subprocess.run(
                [str(candidate), "-c", "exit 0"],
                check=False,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return str(candidate)
    return None


def _h_publication_run() -> str:
    return next(
        run
        for run in _literal_run_blocks(H)
        if "cleanup_partial_draft() {" in run
        and "for discovery_attempt in {1..10}" in run
    )


def test_release_workflow_python_heredocs_are_exact_and_compile() -> None:
    count = 0
    for path in (F, G, H):
        for source_index, source in enumerate(_python_heredocs(path)):
            compile(source, f"{path.name}:heredoc:{source_index}", "exec")
            count += 1
    assert count == 33


def test_sensitive_release_jobs_materialize_one_exact_github_cli() -> None:
    workflows = (C, F, H)
    expected_counts = {C: 2, F: 2, H: 3}
    all_blocks: list[str] = []
    for path in workflows:
        whole = _text(path)
        expected_env = (
            f'  EVOGUARD_PINNED_GH_VERSION: "{PINNED_GH_VERSION}"\n'
            f"  EVOGUARD_PINNED_GH_ARCHIVE_SHA256: "
            f"{PINNED_GH_ARCHIVE_SHA256}\n"
            f'  EVOGUARD_PINNED_GH_ARCHIVE_SIZE: "{PINNED_GH_ARCHIVE_SIZE}"\n'
            f"  EVOGUARD_PINNED_GH_EXECUTABLE: {PINNED_GH_EXECUTABLE}\n"
            f"  EVOGUARD_PINNED_GH_EXECUTABLE_SHA256: "
            f"{PINNED_GH_EXECUTABLE_SHA256}\n"
            f'  EVOGUARD_PINNED_GH_EXECUTABLE_SIZE: "'
            f'{PINNED_GH_EXECUTABLE_SIZE}"'
        )
        assert whole.count(expected_env) == 1
        blocks = _gh_materialization_blocks(path)
        assert len(blocks) == expected_counts[path]
        all_blocks.extend(blocks)
        assert "command -v gh" not in whole
        assert re.search(r"(?m)^\s*gh (?:api|release)\b", whole) is None

    assert len(all_blocks) == 7
    assert len(set(all_blocks)) == 1
    materialize = all_blocks[0]
    expected_url = (
        '"https://github.com/cli/cli/releases/download/'
        'v${EVOGUARD_PINNED_GH_VERSION}/'
        'gh_${EVOGUARD_PINNED_GH_VERSION}_linux_amd64.tar.gz"'
    )
    assert expected_url in materialize
    assert "--proto '=https' --proto-redir '=https' --tlsv1.2" in materialize
    assert '--max-filesize "$EVOGUARD_PINNED_GH_ARCHIVE_SIZE"' in materialize
    assert (
        "printf '%s  %s\\n' \"$EVOGUARD_PINNED_GH_ARCHIVE_SHA256\" "
        '"$archive" | sha256sum --check'
    ) in materialize
    assert 'test "$(stat -c %s "$archive")" = "$EVOGUARD_PINNED_GH_ARCHIVE_SIZE"' in materialize
    assert 'test "$(tar -tzf "$archive" | grep -Fxc -- "$member")" -eq 1' in materialize
    assert 'tar -xOzf "$archive" "$member" > "$candidate"' in materialize
    assert 'tar -xzf' not in materialize
    assert (
        "printf '%s  %s\\n' \"$EXPECTED_GH_SHA256\" \"$candidate\" "
        "| sha256sum --check"
    ) in materialize
    assert 'test "$(stat -c %s "$candidate")" = "$EVOGUARD_PINNED_GH_EXECUTABLE_SIZE"' in materialize
    assert (
        'sudo install -m 0555 -o root -g root "$candidate" '
        '"$EVOGUARD_PINNED_GH_EXECUTABLE"'
    ) in materialize
    assert 'cleanup_materialized_gh() { rm -f -- "$archive" "$candidate"; }' in materialize
    assert "trap cleanup_materialized_gh EXIT" in materialize
    assert 'test "$(stat -c \'%U:%G:%a\' "$prefix")" = "root:root:755"' in materialize
    assert 'test "$(stat -c \'%U:%G:%a\' "$prefix/bin")" = "root:root:755"' in materialize
    assert (
        "root:root:555:1" in materialize
        and materialize.index('tar -xOzf "$archive" "$member"')
        < materialize.index('sudo install -m 0555')
    )
    assert "GH_TOKEN" not in materialize
    assert "secrets." not in materialize
    assert "GITHUB_PATH" not in materialize

    ordered_steps = (
        (C, "preflight", "Materialize the exact GitHub CLI bytes", "Create canonical external controls"),
        (C, "seal", "Materialize the exact GitHub CLI bytes", "Bind raw Git, A/B/C identities"),
        (F, "verify-attestations", "Materialize the exact GitHub CLI bytes", "Snapshot and verify the E SPDX attestation"),
        (F, "seal", "Materialize the exact GitHub CLI bytes", "Bind the outer toolchain"),
        (H, "preflight", "Materialize the exact GitHub CLI bytes", "Bind all public roots"),
        (H, "draft", "Materialize the exact GitHub CLI bytes", "Recheck the closed release set"),
        (H, "publish", "Materialize the exact GitHub CLI bytes", "Recheck the closed release set"),
    )
    for path, job_name, materialize_name, consumer_name in ordered_steps:
        job = _job(path, job_name)
        assert job.count(materialize_name) == 1
        assert job.index(materialize_name) < job.index(consumer_name)
        expected_variable = (
            "vars.EVOGUARD_GH_EXECUTABLE_SHA256"
            if path == C
            else "vars.EVOGUARD_RELEASE_ARTIFACT_GH_EXECUTABLE_SHA256"
        )
        other_variable = (
            "vars.EVOGUARD_RELEASE_ARTIFACT_GH_EXECUTABLE_SHA256"
            if path == C
            else "vars.EVOGUARD_GH_EXECUTABLE_SHA256"
        )
        materialize_step = job[
            job.index(materialize_name) : job.index(consumer_name)
        ]
        assert expected_variable in materialize_step
        assert other_variable not in materialize_step


def test_bootstrap_is_inert_and_contains_only_invalid_post_merge_placeholders() -> None:
    bootstrap = json.loads(
        (ROOT / "security" / "release-pipeline-bootstrap.json").read_text(
            encoding="utf-8"
        )
    )
    assert bootstrap["format"] == "EVOGUARD_RELEASE_PIPELINE_BOOTSTRAP_V1"
    assert bootstrap["activation"] == {
        "EVOGUARD_RELEASE_SOURCE_V2_ENABLED": False,
        "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_ENABLED": False,
        "EVOGUARD_RELEASE_PUBLICATION_ENABLED": False,
    }
    assert bootstrap["policy"]["bootstrap_state"] == (
        "INERT_UNTIL_POST_MERGE_CONFIGURATION"
    )
    required = bootstrap["post_merge_required"]
    assert set(required["workflow_ids"]) == {
        "EVOGUARD_RELEASE_SOURCE_REVERIFY_WORKFLOW_ID",
        "EVOGUARD_RELEASE_SOURCE_RECEIPT_WORKFLOW_ID",
        "EVOGUARD_RELEASE_SOURCE_ADMIT_WORKFLOW_ID",
        "EVOGUARD_RELEASE_ARTIFACT_BUILD_WORKFLOW_ID",
        "EVOGUARD_RELEASE_ARTIFACT_ADMIT_WORKFLOW_ID",
        "EVOGUARD_RELEASE_ARTIFACT_VERIFY_WORKFLOW_ID",
        "EVOGUARD_RELEASE_ARTIFACT_PUBLISH_WORKFLOW_ID",
    }
    assert set(required["workflow_blob_shas"]) == {
        name.replace("_WORKFLOW_ID", "_WORKFLOW_BLOB_SHA")
        for name in required["workflow_ids"]
    }
    for group in ("workflow_ids", "workflow_blob_shas", "public_roots"):
        assert set(required[group].values()) == {"POST_MERGE_REQUIRED"}
    assert required["toolchain"]["EVOGUARD_PROVIDER_ISOLATION_UID"] == 60001
    assert (
        required["toolchain"][
            "EVOGUARD_RELEASE_ARTIFACT_PROVIDER_ISOLATION_UID"
        ]
        == 60002
    )
    assert bootstrap["protected_environments"][
        "evoguard-release-publication"
    ]["secret"] == "EVOGUARD_RELEASE_TAG_DEPLOY_KEY"
    assert set(required["tag_authority"].values()) == {"POST_MERGE_REQUIRED"}
    assert bootstrap["protected_environments"][
        "evoguard-release-draft"
    ]["secret"] is None
    for environment in bootstrap["activation_prerequisites"]["environments"].values():
        assert environment["required_reviewer"] == "MANA-awam"
        assert environment["prevent_self_review"] is True
        assert environment["deployment_branches"] == ["main"]
        assert environment["admin_bypass"] == "DISABLED_AND_MANUALLY_VERIFIED"
    assert bootstrap["activation_prerequisites"]["repository"][
        "strict_status_checks_required"
    ] is True
    assert bootstrap["activation_prerequisites"]["repository"][
        "enforce_admins_required"
    ] is True
    assert bootstrap["activation_prerequisites"]["repository"][
        "immutable_releases_required"
    ] is True
    assert bootstrap["activation_prerequisites"]["repository"][
        "concurrent_contents_writers_frozen_during_publication"
    ] is True
    assert "v*" in bootstrap["activation_prerequisites"]["repository"][
        "release_tag_ruleset"
    ]
    assert bootstrap["post_publication_evidence"]["first_ledger"] == "v4.4.2"
    frozen = bootstrap["post_publication_evidence"]["required_frozen_material"]
    assert "six admission public roots and key IDs" in frozen
    assert "one distinct release-ledger signing public root and key ID" in frozen
    assert "six public roots and key IDs" not in frozen


def test_parent_owned_policy_and_verifier_pack_are_exactly_pinned() -> None:
    policy = json.loads((ROOT / ".evoguard.json").read_text(encoding="utf-8"))
    pack = ROOT / "security" / "release-source-pack"
    candidate_image = (
        "python:3.12-slim@sha256:"
        "57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
    )
    assert json.loads((pack / "pack.json").read_text(encoding="utf-8")) == {
        "description": (
            "Judge-owned release CLI and deterministic asset protocol for "
            "EvoOM Guard protected source admission"
        ),
        "id": "evoom-guard-release-source-protocol",
        "target_type": "cli",
        "version": "1.0.1",
    }
    assert policy["policy_id"] == "evoom-guard-protected-release-source"
    assert policy["policy_version"] == "2"
    assert "*" in policy["protected"]
    assert policy["allow"] == [
        "CHANGELOG.md",
        "PROJECT_STATUS.json",
        "README.md",
        "ROADMAP.md",
        "SECURITY.md",
        "docs/GITHUB_ARTIFACT_ATTESTATIONS.md",
        "docs/PROJECT_STATUS.md",
        "docs/RELEASE_STATUS.md",
        "docs/SBOM.md",
        "docs/architecture/REFACTOR_PROGRAM.md",
        "evoom_guard/__init__.py",
    ]
    assert policy["verifier_pack"] == "security/release-source-pack"
    assert policy["expect_verifier_pack_sha256"] == pack_digest(str(pack))
    bootstrap = json.loads(
        (ROOT / "security" / "release-pipeline-bootstrap.json").read_text(
            encoding="utf-8"
        )
    )
    assert bootstrap["post_merge_required"]["runtime_and_pack"][
        "EVOGUARD_RELEASE_SOURCE_PACK_SHA256"
    ] == pack_digest(str(pack))
    assert policy["blackbox"] is True
    assert policy["blackbox_only"] is True
    assert policy["isolation"] == "docker"
    assert policy["docker_image"] == candidate_image
    assert policy["docker_network"] == "none"
    assert policy["trust_setup_on_host"] is False
    assert policy["require_report_integrity"] == "external_process_isolated"
    assert policy["require_candidate_isolation"] == "docker"
    assert "benchmarks/results.jsonl" not in policy["allow"]
    assert "benchmarks/run-manifest.json" not in policy["allow"]
    assert "evidence/release-ledgers/*" in policy["protected"]
    assert "security/release-ledger-roots/*" in policy["protected"]
    assert "security/release-source-pack/*" in policy["protected"]
    assert "security/release-pipeline-bootstrap.json" in policy["protected"]
    ledger_root = ROOT / "security/release-ledger-roots/v4.4.2.pub.pem"
    assert ledger_root.is_file()
    assert (
        public_key_id(str(ledger_root))
        == "sha256:2b6a4dee04814bed2003f1582ca17aef0fb9de75c765d92aed355bf01483148b"
    )
    previous_ledger_root = ROOT / "security/release-ledger-roots/v4.5.0.pub.pem"
    previous_ledger_key_id = (
        "sha256:0d5dd1a57b8f2b4ec80a197f99bdf73908e7edba82be42ad4666a9fe485b7478"
    )
    assert previous_ledger_root.is_file()
    assert public_key_id(str(previous_ledger_root)) == previous_ledger_key_id
    assert public_key_id(str(previous_ledger_root)) != public_key_id(str(ledger_root))
    latest_ledger_root = ROOT / "security/release-ledger-roots/v4.6.0.pub.pem"
    latest_ledger_key_id = (
        "sha256:ef56c9e65a355d2956201fe8e02abb7c39857d42ee3623d09d71236341ac1da1"
    )
    assert latest_ledger_root.is_file()
    assert public_key_id(str(latest_ledger_root)) == latest_ledger_key_id
    historical_key_ids = {
        public_key_id(str(path))
        for path in (ROOT / "security/release-ledger-roots").glob("v*.pub.pem")
        if path != latest_ledger_root
    }
    assert latest_ledger_key_id not in historical_key_ids
    release_contract = _text(ROOT / "docs/RELEASE_TRUST_PIPELINE.md")
    assert "release-ledger-roots/v4.6.0.pub.pem" in release_contract
    assert latest_ledger_key_id in release_contract
    pack_test = _text(pack / "test_release_protocol.py")
    assert "object_pairs_hook=reject_duplicate_keys" in pack_test
    assert "len(names) == len(set(names))" in pack_test
    assert "info.compress_type == zipfile.ZIP_STORED" in pack_test
    assert "info.compress_size == info.file_size" in pack_test
    assert "package verification code is wrong" in pack_test
    assert "SPDX relationships are not exact" in pack_test
    assert "package.get(\"versionInfo\") == expected_version" in pack_test
    assert "static release version does not match CLI/SPDX" in pack_test
    assert "mutation was accepted" in pack_test
    assert 'doctor_status="$?"' in pack_test
    assert 'test "$doctor_status" -eq 1' in pack_test
    assert "object_pairs_hook=reject_duplicate_keys" in pack_test
    assert 'type(report[key]) is bool for key in ("git", "patch", "supported")' in pack_test
    assert '"platform": "linux-x86_64"' in pack_test
    assert '"python": "3.12.13"' in pack_test
    assert '"git": False' in pack_test
    assert '"patch": False' in pack_test
    assert '"supported": False' in pack_test
    assert '"$1" -I "$work/evo-guard.pyz" doctor >/dev/null' not in pack_test

    source = _text(A)
    assert source.count(f"CANDIDATE_IMAGE: {candidate_image}") == 3
    assert "ref: ${{ needs.metadata.outputs.parent_sha }}" in source
    assert 'path: base' in source
    assert (
        '--verifier-pack "$GITHUB_WORKSPACE/base/security/release-source-pack"'
        in source
    )
    assert (
        '-r "$GITHUB_WORKSPACE/base/security/judge-requirements.lock"' in source
    )
    assert '--config "$GITHUB_WORKSPACE/base/.evoguard.json"' in source
    assert "Validate the parent-owned release policy" in source
    assert (
        'python -I "$GITHUB_WORKSPACE/base/tools/ci/'
        'validate_release_candidate_scope.py"' in source
    )
    assert '--base "$GITHUB_WORKSPACE/base"' in source
    assert '--candidate "$GITHUB_WORKSPACE/candidate"' in source
    assert candidate_scope.ALLOWED_PATHS == tuple(policy["allow"])
    assert "target.parents.length !== 1" in source
    assert "branch.protected !== true" in source
    assert source.count("fetch-depth: 0") >= 2
    assert (
        "Verify exact dev0 benchmark evidence carry-forward with parent code"
        in source
    )
    assert "sys.path.insert(0, str(base))" in source
    assert "candidate / 'benchmarks/run-manifest.json'" in source
    assert "base / 'benchmarks/run-manifest.json'" in source
    assert "ENGINE_VERSION != '4.6.0.dev0'" in source
    assert "trusted parent benchmark rejected" in source
    assert "engine_version='4.6.0'" in source
    assert "require_release_promotion=True" in source
    assert source.count("required_history_tip='HEAD'") == 2
    assert "relation=exact-release-version-transition" in source
    assert "benchmarks/results.jsonl" not in source


def test_release_candidate_scope_is_enforced_by_the_real_preflight() -> None:
    policy = json.loads((ROOT / ".evoguard.json").read_text(encoding="utf-8"))
    protected = tuple(policy["protected"])
    allowed = tuple(policy["allow"])

    allowed_result = evaluate_candidate_preflight(
        CandidatePreflightRequest(
            repo_path=str(ROOT),
            changed_paths=(
                "CHANGELOG.md",
                "README.md",
                "evoom_guard/__init__.py",
            ),
            protected=protected,
            allow=allowed,
            strict_harness=True,
        )
    )
    assert allowed_result.may_execute is True
    assert allowed_result.protected_violations == ()

    protected_result = evaluate_candidate_preflight(
        CandidatePreflightRequest(
            repo_path=str(ROOT),
            changed_paths=(
                ".evoguard.json",
                "security/release-ledger-roots/v4.4.2.pub.pem",
                "tests/test_raae_release_pipeline_workflows.py",
            ),
            protected=protected,
            allow=allowed,
            strict_harness=True,
        )
    )
    assert protected_result.may_execute is False
    assert protected_result.protected_violations == (
        ".evoguard.json",
        "security/release-ledger-roots/v4.4.2.pub.pem",
        "tests/test_raae_release_pipeline_workflows.py",
    )

    ordinary_source = evaluate_candidate_preflight(
        CandidatePreflightRequest(
            repo_path=str(ROOT),
            changed_paths=("evoom_guard/guard.py",),
            protected=protected,
            allow=allowed,
            strict_harness=True,
        )
    )
    assert ordinary_source.may_execute is False
    assert ordinary_source.protected_violations == ("evoom_guard/guard.py",)

    ordinary_deletion = evaluate_candidate_preflight(
        CandidatePreflightRequest(
            repo_path=str(ROOT),
            changed_paths=("evoom_guard/__init__.py",),
            deleted_paths=("evoom_guard/guard.py",),
            protected=protected,
            allow=allowed,
            strict_harness=True,
        )
    )
    assert ordinary_deletion.may_execute is False
    assert ordinary_deletion.protected_violations == ("evoom_guard/guard.py",)


def _write_scope_tree(
    root: Path,
    *,
    version_assignment: str,
    readme: str = "base\n",
    security: str = "base security policy\n",
    guard: str | None = None,
) -> None:
    package = root / "evoom_guard"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        "# frozen prefix\n"
        f'{version_assignment}\n'
        "# frozen suffix\n",
        encoding="utf-8",
        newline="\n",
    )
    (root / "README.md").write_text(readme, encoding="utf-8", newline="\n")
    (root / "SECURITY.md").write_text(
        security,
        encoding="utf-8",
        newline="\n",
    )
    if guard is not None:
        (package / "guard.py").write_text(
            guard,
            encoding="utf-8",
            newline="\n",
        )


def test_release_scope_validator_accepts_only_the_exact_version_byte_change(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    _write_scope_tree(
        base,
        version_assignment='__version__ = "4.6.0.dev0"',
    )
    _write_scope_tree(
        candidate,
        version_assignment='__version__ = "4.6.0"',
        readme="candidate\n",
        security="candidate security policy\n",
    )

    assert candidate_scope.validate_candidate_scope(base, candidate) == (
        "README.md",
        "SECURITY.md",
        "evoom_guard/__init__.py",
    )


@pytest.mark.parametrize(
    "evidence_path",
    (
        "benchmarks/results.jsonl",
        "benchmarks/run-manifest.json",
    ),
)
def test_release_scope_validator_rejects_benchmark_evidence_refresh(
    evidence_path: str,
) -> None:
    with pytest.raises(
        candidate_scope.CandidateScopeError,
        match=re.escape(evidence_path),
    ):
        candidate_scope.validate_changed_paths(
            (
                evidence_path,
                candidate_scope.VERSION_PATH,
            )
        )


@pytest.mark.parametrize(
    "alias",
    (
        "README.MD",
        "Docs/SBOM.md",
        "evoom_guard/__INIT__.py",
    ),
)
def test_release_scope_validator_rejects_case_aliases(alias: str) -> None:
    with pytest.raises(
        candidate_scope.CandidateScopeError,
        match="outside the exact-case scope",
    ):
        candidate_scope.validate_changed_paths(
            tuple(sorted((candidate_scope.VERSION_PATH, alias)))
        )


def test_release_scope_validator_rejects_an_unlisted_source_edit(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    _write_scope_tree(
        base,
        version_assignment='__version__ = "4.6.0.dev0"',
        guard="VALUE = 1\n",
    )
    _write_scope_tree(
        candidate,
        version_assignment='__version__ = "4.6.0"',
        guard="VALUE = 2\n",
    )

    with pytest.raises(
        candidate_scope.CandidateScopeError,
        match=r"evoom_guard/guard\.py",
    ):
        candidate_scope.validate_candidate_scope(base, candidate)


def test_release_scope_validator_rejects_an_unlisted_source_deletion(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    _write_scope_tree(
        base,
        version_assignment='__version__ = "4.6.0.dev0"',
        guard="VALUE = 1\n",
    )
    _write_scope_tree(
        candidate,
        version_assignment='__version__ = "4.6.0"',
    )

    with pytest.raises(
        candidate_scope.CandidateScopeError,
        match=r"evoom_guard/guard\.py",
    ):
        candidate_scope.validate_candidate_scope(base, candidate)


def test_release_scope_validator_rejects_an_allowed_path_deletion(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    _write_scope_tree(
        base,
        version_assignment='__version__ = "4.6.0.dev0"',
    )
    _write_scope_tree(
        candidate,
        version_assignment='__version__ = "4.6.0"',
    )
    (candidate / "README.md").unlink()

    with pytest.raises(
        candidate_scope.CandidateScopeError,
        match="may not add or delete an allowed path: README.md",
    ):
        candidate_scope.validate_candidate_scope(base, candidate)


@pytest.mark.parametrize(
    "candidate_init",
    (
        '# frozen prefix\n__version__ = "4.6.0"\n# changed suffix\n',
        '# frozen prefix\n__version__ = "4.4.3"\n# frozen suffix\n',
        (
            '# frozen prefix\n__version__ = "4.6.0"\n'
            'SECOND_VERSION = "4.6.0"\n# frozen suffix\n'
        ),
        (
            "# frozen prefix\n"
            'import os\n__version__ = "4.6.0"\n# frozen suffix\n'
        ),
    ),
)
def test_release_scope_validator_rejects_version_file_mutations(
    tmp_path: Path,
    candidate_init: str,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    _write_scope_tree(
        base,
        version_assignment='__version__ = "4.6.0.dev0"',
    )
    _write_scope_tree(
        candidate,
        version_assignment='__version__ = "4.6.0"',
    )
    (candidate / candidate_scope.VERSION_PATH).write_text(
        candidate_init,
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(
        candidate_scope.CandidateScopeError,
        match="may change only the exact",
    ):
        candidate_scope.validate_candidate_scope(base, candidate)


def test_a_b_c_separate_candidate_execution_provider_and_key_access() -> None:
    a = _text(A)
    b = _text(B)
    c_preflight = _job(C, "preflight")
    c_seal = _job(C, "seal")

    assert "permissions: {}" in a
    assert "id-token: write" not in a
    assert "attestations: write" not in a
    assert "contents: write" not in a
    assert "secrets." not in a

    assert "actions/checkout@" not in b
    assert "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2_PRIVATE_KEY_B64" not in b
    assert "attestations: write" in b
    assert "id-token: write" in b

    assert "environment:" not in c_preflight
    assert "secrets." not in c_preflight
    assert "evoguard-release-source-v2-controls-" in c_preflight
    assert "environment: evoguard-release-source-v2" in c_seal
    assert (
        "secrets.EVOGUARD_RELEASE_SOURCE_ADMISSION_V2_PRIVATE_KEY_B64"
        in c_seal
    )
    assert "provider identity can read the V2 signing key" in c_seal
    assert c_seal.index("Freshly verify B") < c_seal.index("--sign-key")


def test_e_build_and_attestation_are_capability_separated() -> None:
    preflight = _job(E, "preflight")
    build = _job(E, "build")
    attest = _job(E, "attest")

    assert "parent_tree_sha: ${{ steps.bind.outputs.parent_tree_sha }}" in preflight
    assert "github.rest.git.getCommit" in preflight
    assert "core.setOutput('parent_tree_sha', parentTreeSha)" in preflight
    assert "actions/checkout@" in build
    assert "ops/build_pyz.py" in build
    assert "ops/generate_spdx_sbom.py" in build
    assert "Checkout only the one-parent trusted release tools" in build
    assert "cat-file blob \"$BUILD_TOOL_BLOB_SHA\"" in build
    assert "hash-object --no-filters" in build
    assert 'dst=/trusted-tools,readonly' in build
    assert 'root="/candidate"' in build
    assert "PYZ members do not equal packaged source" in build
    assert "PYZ member differs from source" in build
    assert "actions/attest@" not in build
    assert "attestations: write" not in build
    assert "id-token: write" not in build
    assert "contents: write" not in build
    assert "secrets." not in build
    assert "python -I admitted-source/ops/build_pyz.py" not in build
    assert "--network none" in build
    assert "test \"$parent_tree\" = \"$PARENT_TREE_SHA\"" in build
    assert (
        'jq -er .parent_commit_sha "$RUNNER_TEMP/e-inputs/context.json"'
        in build
    )
    assert (
        'jq -er .parent_tree_sha "$RUNNER_TEMP/e-inputs/context.json"'
        in build
    )
    assert 'jq -er .base_sha "$RUNNER_TEMP/e-inputs/context.json"' not in build
    assert (
        'jq -er .base_tree_sha "$RUNNER_TEMP/e-inputs/context.json"'
        not in build
    )
    assert "'trusted_build_parent_tree_sha': os.environ['PARENT_TREE_SHA']" in build
    assert "'build_container': {" in build
    assert "'reference': os.environ['BUILD_IMAGE']" in build
    assert "'sha256': os.environ['BUILD_IMAGE'].rsplit('@sha256:', 1)[1]" in build
    assert "'network': 'none'" in build
    assert "--read-only" in build
    assert "--cap-drop ALL" in build
    assert "--security-opt no-new-privileges" in build
    assert "--user \"$(id -u):$(id -g)\"" in build
    assert "--mount \"type=bind,src=$GITHUB_WORKSPACE/admitted-source,dst=/candidate,readonly\"" in build
    assert "--ulimit fsize=134217728:134217728" in build
    assert "sudo chown" not in build
    assert "sudo chmod" not in build
    assert build.count("docker run --rm") == 2
    assert "doctor --json \\" in build
    assert "> /tmp/doctor.json 2> /tmp/doctor.stderr" in build
    assert 'doctor_status="$?"' in build
    assert 'test "$doctor_status" -eq 1' in build
    assert "test ! -s /tmp/doctor.stderr" in build
    assert '"platform": "linux-x86_64"' in build
    assert '"python": "3.12.13"' in build
    assert '"git": False' in build
    assert '"patch": False' in build
    assert '"supported": False' in build
    assert "object_pairs_hook=reject_duplicate_keys" in build
    assert "parse_constant=reject_constant" in build
    assert "or set(report) != set(expected)" in build
    assert (
        "or any(type(report[key]) is not expected_types[key] for key in expected)"
        in build
    )
    assert "release asset doctor contract is not exact" in build
    assert "doctor >/dev/null" not in build
    assert build.count('--env "EXPECTED_VERSION=$EXPECTED_VERSION"') == 2
    assert "container build output is not closed" in build
    assert "PYZ preamble is not canonical" in build
    assert "SPDX relationships are not exact" in build
    assert "SPDX bytes are not canonical EvoGuard JSON" in build

    assert "attestations: write" in attest
    assert "id-token: write" in attest
    assert "actions/checkout@" not in attest
    assert "python -I admitted-source/ops/build_pyz.py" not in attest
    assert "python -I /trusted-tools/build_pyz.py" not in attest
    assert "python -I /trusted-tools/generate_spdx_sbom.py" not in attest
    assert "docker run" not in attest
    assert "python -I ${{ runner.temp }}/e-output/evo-guard.pyz" not in attest
    assert attest.count(
        "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d"
    ) == 3
    assert attest.count(
        "subject-path: ${{ runner.temp }}/e-output/evo-guard.pyz"
    ) == 2
    assert (
        "sbom-path: ${{ runner.temp }}/e-output/evo-guard.spdx.json"
        in attest
    )
    assert attest.count(
        "subject-path: ${{ runner.temp }}/e-output/evo-guard.spdx.json"
    ) == 1
    assert "Attest the exact executable with its SPDX SBOM" in attest
    assert "Attest the exact SPDX bytes" in attest
    assert "unprivileged build output set is not closed" in attest
    assert "expected_version must be a reviewed stable X.Y.Z version" in _text(E)
    assert "compressed member:" in build
    assert "PYZ release version does not match SPDX" in attest
    assert "Independently enforce the complete static PYZ and SPDX contract" in attest
    assert "trusted expected release version is not stable X.Y.Z" in attest
    assert "ZIP has trailing bytes" in attest
    assert "SPDX relationships are not exact" in attest
    assert "SPDX bytes are not canonical EvoGuard JSON" in attest
    assert "static PYZ version does not bind the trusted expected version" in attest
    assert "builder controls do not bind the trusted parent tree" in attest
    assert "builder controls do not bind the exact networkless container" in attest


def test_e_doctor_validator_accepts_only_the_exact_typed_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = next(block for block in _literal_run_blocks(E) if "doctor --json" in block)
    opener = "python -I -c '\"'\"'\n"
    start = run.index(opener, run.index("doctor --json")) + len(opener)
    source = run[start : run.index("\n'\"'\"'\n", start)]
    report_path = tmp_path / "doctor.json"
    source = source.replace('"/tmp/doctor.json"', repr(report_path.as_posix()))
    compile(source, f"{E.name}:doctor-validator", "exec")
    monkeypatch.setenv("EXPECTED_VERSION", "4.4.0")

    exact = {
        "tool": "evoguard",
        "version": "4.4.0",
        "platform": "linux-x86_64",
        "python": "3.12.13",
        "git": False,
        "patch": False,
        "supported": False,
    }
    report_path.write_text(json.dumps(exact), encoding="utf-8")
    exec(compile(source, f"{E.name}:doctor-validator", "exec"), {})

    rejected = (
        '{"tool":"evoguard","tool":"other","version":"4.4.0",'
        '"platform":"linux-x86_64","python":"3.12.13",'
        '"git":false,"patch":false,"supported":false}',
        json.dumps({**exact, "git": 0}),
        json.dumps({**exact, "git": float("nan")}),
    )
    for payload in rejected:
        report_path.write_text(payload, encoding="utf-8")
        with pytest.raises((SystemExit, ValueError)):
            exec(compile(source, f"{E.name}:doctor-validator", "exec"), {})


def test_f_creates_two_fresh_provider_bound_raae_envelopes() -> None:
    preflight = _job(F, "preflight")
    attestations = _job(F, "verify-attestations")
    seal = _job(F, "seal")

    assert "environment:" not in preflight
    assert "secrets." not in preflight
    assert "EVOGUARD_RELEASE_ASSET_F_CONTROLS_V1" in preflight
    assert "'evo-guard.pyz': descriptor('evo-guard.pyz')" in preflight
    assert (
        "'evo-guard.spdx.json': descriptor('evo-guard.spdx.json')" in preflight
    )
    assert "PARENT_TREE_SHA=\"$parent_tree\"" in preflight
    assert "export PARENT_SHA PARENT_TREE_SHA" in preflight
    assert (
        'jq -er .parent_commit_sha "$RUNNER_TEMP/f-controls/context.json"'
        in preflight
    )
    assert (
        'jq -er .parent_tree_sha "$RUNNER_TEMP/f-controls/context.json"'
        in preflight
    )
    assert 'jq -er .base_sha "$RUNNER_TEMP/f-controls/context.json"' not in preflight
    assert (
        'jq -er .base_tree_sha "$RUNNER_TEMP/f-controls/context.json"'
        not in preflight
    )
    assert "'trusted_build_parent_tree_sha': os.environ['PARENT_TREE_SHA']" in preflight
    assert "'build_container': {" in preflight
    assert "'reference': os.environ['BUILD_IMAGE']" in preflight
    assert "'sha256': os.environ['BUILD_IMAGE'].rsplit('@sha256:', 1)[1]" in preflight
    assert "'network': 'none'" in preflight
    assert "environment:" not in attestations
    assert "secrets." not in attestations
    assert "attestations: read" in attestations
    assert "github-attestation-receipt" in attestations
    assert "create_slsa_receipt evo-guard.pyz build-provenance" in attestations
    assert (
        "create_slsa_receipt evo-guard.spdx.json spdx-provenance"
        in attestations
    )
    assert "verify_spdx_attestation.py" in attestations
    assert (
        'sudo install -d -m 0700 -o "$PROVIDER_UID" -g "$PROVIDER_GID" \\\n'
        "            /run/evoguard-spdx/gh-config"
        in attestations
    )
    assert (
        """test "$(sudo stat -c '%u:%g:%a' /run/evoguard-spdx/gh-config)" = \\
            "$PROVIDER_UID:$PROVIDER_GID:700\""""
        in attestations
    )
    direct_start = attestations.index("sudo --preserve-env=GH_TOKEN setpriv")
    direct_end = attestations.index("sudo setpriv", direct_start)
    direct_spdx_provider = attestations[direct_start:direct_end]
    direct_verify = direct_spdx_provider.index('"$1" attestation verify "$2"')
    for isolation_control in (
        "export GH_CONFIG_DIR=/run/evoguard-spdx/gh-config",
        'export HOME="$GH_CONFIG_DIR" TMPDIR="$GH_CONFIG_DIR"',
        "export NO_COLOR=1 CLICOLOR=0 GIT_TERMINAL_PROMPT=0 "
        "GH_PROMPT_DISABLED=1",
    ):
        assert isolation_control in direct_spdx_provider
        assert direct_spdx_provider.index(isolation_control) < direct_verify
    assert "'version': '4.3.0'" in preflight
    assert ".external_settings.runtime.version" in attestations
    assert "evo-guard $RUNTIME_VERSION" in attestations
    assert "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_PRIVATE_KEY_B64" not in attestations
    assert "evoguard-release-artifact-v1-complete-controls-" in attestations
    assert "complete F control inventory" not in attestations
    assert "find \"$RUNNER_TEMP/f-controls-complete\"" in attestations
    assert (
        """root_attestation_evidence=(
            build-provenance-verification.json
            build-provenance-verification-output.json
            spdx-provenance-verification.json
            spdx-provenance-verification-output.json
          )"""
        in attestations
    )
    assert (
        """provider_attestation_evidence=(
            sbom-attestation-output.json
            sbom-attestation-receipt.json
          )"""
        in attestations
    )
    assert 'for name in "${root_attestation_evidence[@]}"; do' in attestations
    assert 'for name in "${provider_attestation_evidence[@]}"; do' in attestations
    assert (
        '            "${root_attestation_evidence[@]}" \\\n'
        '            "${provider_attestation_evidence[@]}"; do'
        in attestations
    )
    assert "/run/evoguard-spdx/output/*" not in attestations
    assert (
        '"/run/evoguard-spdx/output/$name" \\\n'
        '              "$RUNNER_TEMP/f-controls-complete/$name"'
        in attestations
    )

    assert "environment: evoguard-release-artifact-v1" in seal
    assert "needs: [preflight, verify-attestations]" in _text(F)
    assert "verify-github-attestation-receipt" in seal
    assert "complete F manifest does not bind all attestation bytes" in seal
    assert (
        "secrets.EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_PRIVATE_KEY_B64"
        in seal
    )
    assert seal.count("seal-github-release-artifact-admission") == 1
    assert "seal_asset evo-guard.pyz" in seal
    assert "seal_asset evo-guard.spdx.json" in seal
    assert "$RUNNER_TEMP/evo-guard.pyz.raae" in seal
    assert "$RUNNER_TEMP/evo-guard.spdx.json.raae" in seal
    assert "outer provider can read the RAAE signing key" in seal
    assert "live_provider_reverification" in seal
    assert "provider/github-attestation-receipt.json" in seal
    assert "RAAE provider evidence size is unsafe" in seal
    assert "cmp --silent" in seal
    assert "actions/checkout@" not in seal


def test_g_verifies_both_envelopes_and_required_negative_matrix() -> None:
    g = _job(G, "detached-verify")
    assert "secrets." not in g
    assert "environment:" not in g
    assert "verify-github-release-artifact-admission" in g
    assert "for name in evo-guard.pyz evo-guard.spdx.json" in g
    assert "cross-artifact-substitution" in g
    for label in (
        "tampered-pyz",
        "tampered-sbom",
        "tampered-bundle",
        "cross-artifact-substitution",
        "wrong-raae-root",
        "wrong-outer-git-pin",
        "wrong-source-gh-pin",
    ):
        assert label in g
    assert 'test "$(wc -l < "$RUNNER_TEMP/raae-negative-results.txt")" -eq 7' in g
    assert "live_provider_reverification" in g
    assert "= \"false\"" in g
    assert "publication-controls.json" in g
    assert "evoguard-release-artifact-v1-complete-controls-" in g
    assert "verify-github-attestation-receipt" in g
    assert "verify_slsa_receipt evo-guard.pyz build-provenance" in g
    assert "verify_slsa_receipt evo-guard.spdx.json spdx-provenance" in g
    assert "verify_spdx_attestation.py" in g
    assert "'attestation_evidence': {" in g
    for source, destination in (
        ("evo-guard.pyz", "tampered-artifact.pyz"),
        ("evo-guard.spdx.json", "tampered-sbom.json"),
        ("evo-guard.pyz.raae", "tampered.raae"),
    ):
        assert (
            "install -m 0600 \\\n"
            f'            "/run/evoguard-raae-detached-approved/inputs/{source}" \\\n'
            f'            "$RUNNER_TEMP/{destination}"'
            in g
        )
        assert (
            f'cp "/run/evoguard-raae-detached-approved/inputs/{source}" '
            f'"$RUNNER_TEMP/{destination}"'
            not in g
        )


def test_h_reverifies_then_writes_only_an_exact_draft() -> None:
    preflight = _job(H, "preflight")
    draft = _job(H, "draft")
    publish = _job(H, "publish")
    whole = _text(H)

    assert (
        "vars.EVOGUARD_RELEASE_PUBLICATION_ENABLED ==\n"
        "      github.event.workflow_run.head_sha"
    ) in preflight
    assert "contents: write" not in preflight
    assert "environment:" not in preflight
    assert "verify-github-release-artifact-admission" in preflight
    assert "verify_one evo-guard.pyz" in preflight
    assert "verify_one evo-guard.spdx.json" in preflight

    assert "environment: evoguard-release-draft" in draft
    assert "contents: write" not in draft
    assert "contents: read" in draft
    assert "actions/checkout@" not in draft
    assert "ops/build_pyz.py" not in draft
    assert "ops/generate_spdx_sbom.py" not in draft
    assert "python -I" not in draft
    assert "secrets." not in draft
    assert "gh release create" not in draft
    assert "--draft" not in draft
    assert 'git/ref/tags/$tag' in draft
    assert 'test "$tag_status" != "404"' in draft
    assert "the approval could not prove tag absence" in draft
    assert "Approve the exact intent without creating a tag or release" in draft
    assert "the approval refuses an existing release" in draft
    assert "RAAE-bound builder version does not match SPDX" in whole
    assert "PYZ release version does not match SPDX" in whole
    assert "'version': '4.3.0'" in _text(G)
    assert ".external_settings.runtime.version" in preflight
    assert "evo-guard $RUNTIME_VERSION" in preflight
    assert "evo-guard $RELEASE_VERSION" not in preflight
    assert "environment: evoguard-release-publication" in publish
    assert "contents: write" in publish
    immutable_admin_api = '"repos/$GITHUB_REPOSITORY/immutable-releases"'
    assert immutable_admin_api not in draft
    assert immutable_admin_api not in publish
    assert "secrets." not in draft
    assert (
        "PUBLICATION_AUTHORIZED_TARGET: "
        "${{ vars.EVOGUARD_RELEASE_PUBLICATION_ENABLED }}"
    ) in draft
    assert (
        "PUBLICATION_AUTHORIZED_TARGET: "
        "${{ vars.EVOGUARD_RELEASE_PUBLICATION_ENABLED }}"
    ) in publish
    assert draft.count(
        'test "$PUBLICATION_AUTHORIZED_TARGET" = "$TARGET_SHA"'
    ) == 1
    assert publish.count(
        'test "$PUBLICATION_AUTHORIZED_TARGET" = "$TARGET_SHA"'
    ) == 2
    assert "GITHUB_TOKEN cannot receive repository Administration:read" in draft
    assert '"X-GitHub-Api-Version: 2026-03-10"' in whole
    assert "--method PATCH" in publish
    assert '{"draft":false}' in publish
    assert "release.get('immutable') is not True" in publish
    assert "published tag does not bind the admitted target" in publish
    assert "for attempt in {1..10}" in publish
    assert "for discovery_attempt in {1..10}" in publish
    assert "for cleanup_attempt in {1..10}" in publish
    assert 'if test "$discovery_status" -ne 75; then' in publish
    assert 'if test "$cleanup_status" -ne 75; then' in publish
    assert 'if release_id="$(' in publish
    assert 'if cleanup_id="$(' in publish
    assert "set +e\n            release_id=" not in publish
    assert publish.count("raise SystemExit(75)") == 2
    assert "sleep 2" in publish
    assert publish.count(
        '"$EVOGUARD_PINNED_GH_EXECUTABLE" release create'
    ) == 1
    assert "did not become visible within the bounded window" in publish
    assert "the visible draft is not uniquely attributable; preserving it" in publish
    assert "release pagination page is outside bounds" in publish
    assert "release pagination item is not an object" in publish
    assert "incomplete draft tag is not unique" in publish
    assert "failed to delete the uniquely attributable incomplete draft" in publish
    assert "draft deletion could not be proven by an exact HTTP 404" in publish
    assert "/^HTTP\\/[0-9.]+ [0-9][0-9][0-9]( |$)/" in publish
    assert 'test "$cleanup_http_status" = 404' in publish
    assert 'cleanup_partial_draft "$discovery_status"' in publish
    assert "--draft" in publish
    assert "H never reuses or mutates an existing ref" in publish
    assert "prove_tag_absent before" in publish
    assert "prove_tag_absent after" in publish
    assert "cleanup_partial_draft" in publish
    assert "removed only the incomplete draft created by this H run" in publish
    assert "cleanup_verified_unpublished_draft" in publish
    assert "removed exact unpublished draft after a pre-PATCH failure" in publish
    assert "secrets.EVOGUARD_RELEASE_TAG_DEPLOY_KEY" in publish
    assert "vars.EVOGUARD_RELEASE_TAG_DEPLOY_KEY_FINGERPRINT" in _text(F)
    assert "vars.EVOGUARD_RELEASE_TAG_DEPLOY_KEY_FINGERPRINT" in _text(G)
    assert "vars.EVOGUARD_RELEASE_TAG_DEPLOY_KEY_FINGERPRINT" not in publish
    assert "tag_deploy_key_fingerprint" in preflight
    assert "expected_tag_deploy_key_fingerprint" in publish
    assert "actual_tag_key_fingerprint" in publish
    assert "HostKeyAlgorithms=ssh-ed25519" in publish
    assert "IdentityAgent=none" in publish
    assert "ssh -F /dev/null" in publish
    assert "git@github.com:$GITHUB_REPOSITORY.git" in publish
    assert (
        "github.com ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    ) in publish
    assert "ssh://git@ssh.github.com:443" not in publish
    assert "tag-deploy-key-authentication.txt" not in publish
    assert 'local trapped_failure=$?' in publish
    assert 'local failure="${1:-$trapped_failure}"' in publish
    assert (
        'if "$EVOGUARD_PINNED_GH_EXECUTABLE" api --include '
        '"repos/$GITHUB_REPOSITORY/git/ref/tags/$tag"'
        in publish
    )
    assert (
        'set +e\n          "$EVOGUARD_PINNED_GH_EXECUTABLE" api --include '
        '"repos/$GITHUB_REPOSITORY/git/ref/tags/$tag"'
    ) not in publish
    assert publish.count("cleanup_verified_unpublished_draft 1") == 2
    assert "git -C \"$tag_repo\" push" in publish
    assert '"$TARGET_SHA:refs/tags/$tag"' in publish
    assert '":refs/tags/$tag"' in publish
    assert '--force-with-lease="refs/tags/$tag:$TARGET_SHA"' in publish
    assert "deploy-key tag push failed before ref proof" in publish
    assert 'cleanup_verified_unpublished_draft "$tag_push_rc"' in publish
    assert "deploy-key push did not prove a newly created tag" in publish
    assert "cleanup-exact-tag.json" in publish
    assert "cleanup-exact-tag.response" not in publish
    assert "tag deletion was not proven" in publish
    assert "tag_created=true" in publish
    assert "tag-created-by-deploy-key.json" in publish
    assert "preserving the draft for manual recovery" in publish
    assert publish.index("trap cleanup_verified_unpublished_draft ERR") < publish.index(
        'test -n "$TAG_DEPLOY_KEY"'
    )
    assert 'if ! GIT_SSH_COMMAND="$tag_ssh_command"' not in publish[
        publish.index('"$TARGET_SHA:refs/tags/$tag"') - 400 :
        publish.index('"$TARGET_SHA:refs/tags/$tag"') + 100
    ]
    assert publish.index('"$TARGET_SHA:refs/tags/$tag"') < publish.index(
        "printf '%s\\n' '{\"draft\":false}'"
    )
    assert publish.index("trap cleanup_verified_unpublished_draft ERR") < publish.index(
        'trap - ERR\n          "$EVOGUARD_PINNED_GH_EXECUTABLE" api'
    )
    assert publish.count("release.get('author', {}).get('id')") >= 4
    assert publish.count("41898282") >= 4
    assert "--paginate --slurp" in publish
    assert "created draft release is not unique" in publish
    assert "release.get('target_commitish') != target" in publish
    assert "release.get('draft') is not True" in publish
    assert "group: evoguard-release-publication" in whole
    assert "release.get('name') != record['tag']" in publish
    assert "mutable display metadata, not a trust root" in publish
    for heading in (
        "## Status and support",
        "## Highlights",
        "## Upgrade impact",
        "## Security boundary",
        "## Compatibility",
        "## Assets and verification",
        "## Known limitations",
        "## Evidence and full changelog",
    ):
        assert publish.count(heading) == 2
    release_body_scripts = re.findall(
        r'MARKER="\$marker" python - "\$record" <<\'PY\'\n'
        r"(?P<script>.*?)\n"
        r"\s+PY",
        publish,
        re.DOTALL,
    )
    assert len(release_body_scripts) == 2
    assert release_body_scripts[0] == release_body_scripts[1]
    assert publish.count("never to `main`") == 2
    assert publish.count("docs/ASSURANCE.md") == 4
    assert "asset.get('digest') != f\"sha256:{expected['sha256']}\"" in publish
    assert "RELEASE_ID: ${{ steps.create.outputs.release_id }}" in publish
    assert "gh release edit" not in whole
    assert "gh release upload" not in whole
    assert "gh release edit" not in whole
    assert "gh release upload" not in whole
    assert "--latest" not in whole
    assert "evo-guard.pyz.raae" not in draft
    assert "evoguard-release-artifact-v1-complete-controls-" in preflight
    assert "G selector attestation digest mismatch" in preflight
    assert "host_tools" in preflight
    assert preflight.count("--no-new-privs") >= 1
    assert "--reuid=\"$OUTER_PROVIDER_UID\"" in preflight
    assert "publication host tool changed" in draft
    assert "publication host tool changed" in publish
    assert "observed != expected_tools.get(name)" in draft
    assert "observed != expected_tools.get(name)" in publish
    assert publish.count("$RUNNER_TEMP/publication-final/") >= 3


def test_h_draft_discovery_retries_only_an_absent_release(tmp_path: Path) -> None:
    heredocs = _python_heredocs(H)
    discovery = next(
        source
        for source in heredocs
        if "created draft release is not unique" in source
    )
    cleanup = next(
        source
        for source in heredocs
        if "def assets_match" in source
    )
    target = "a" * 40
    body = "deterministic release body"
    record = {
        "tag": "v4.4.0",
        "target_sha": target,
        "assets": {
            "evo-guard.pyz": {"sha256": "1" * 64, "size": 11},
            "evo-guard.spdx.json": {"sha256": "2" * 64, "size": 22},
            "SHA256SUMS": {"sha256": "3" * 64, "size": 33},
        },
    }
    release = {
        "id": 123,
        "tag_name": record["tag"],
        "name": record["tag"],
        "target_commitish": target,
        "draft": True,
        "prerelease": False,
        "body": body,
        "author": {"login": "github-actions[bot]", "id": 41898282},
        "assets": [
            {
                "name": name,
                "state": "uploaded",
                "size": descriptor["size"],
                "digest": f"sha256:{descriptor['sha256']}",
            }
            for name, descriptor in record["assets"].items()
        ],
    }
    record_path = tmp_path / "record.json"
    pages_path = tmp_path / "pages.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    environment = {**os.environ, "RELEASE_BODY": body}

    def invoke(source: str, pages: object) -> subprocess.CompletedProcess[str]:
        pages_path.write_text(json.dumps(pages), encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-",
                str(record_path),
                str(pages_path),
            ],
            input=source,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    for source in (discovery, cleanup):
        invisible = invoke(source, [[]])
        assert invisible.returncode == 75
        assert invisible.stdout == ""

        visible = invoke(source, [[release]])
        assert visible.returncode == 0
        assert visible.stdout.strip() == "123"

        duplicate = invoke(source, [[release, {**release, "id": 124}]])
        assert duplicate.returncode == 2

        hostile_same_tag = invoke(
            source,
            [[release, {**release, "id": 124, "body": "other", "target_commitish": "b" * 40}]],
        )
        assert hostile_same_tag.returncode == 2

        wrong_body = invoke(source, [[{**release, "body": body + "\n"}]])
        assert wrong_body.returncode == 2

        wrong_asset = {
            **release,
            "assets": [
                *release["assets"][:-1],
                {**release["assets"][-1], "digest": f"sha256:{'4' * 64}"},
            ],
        }
        mutated = invoke(source, [[wrong_asset]])
        assert mutated.returncode == 2

        for malformed in ([], {}, [{}], [[1]]):
            rejected = invoke(source, malformed)
            assert rejected.returncode == 2


def test_h_draft_discovery_bash_control_flow_survives_err_trap(
    tmp_path: Path,
) -> None:
    bash = _working_bash()
    if bash is None:
        pytest.skip("a working Bash is required to execute the H retry loop")

    run = _h_publication_run()
    start = run.index('release_id=""\nfor discovery_attempt in {1..10}; do')
    end = run.index("trap - ERR", start) + len("trap - ERR")
    retry_loop = run[start:end]
    target = "a" * 40
    body = "deterministic release body"
    record = {
        "tag": "v4.4.0",
        "target_sha": target,
        "assets": {
            "evo-guard.pyz": {"sha256": "1" * 64, "size": 11},
            "evo-guard.spdx.json": {"sha256": "2" * 64, "size": 22},
            "SHA256SUMS": {"sha256": "3" * 64, "size": 33},
        },
    }
    release = {
        "id": 123,
        "tag_name": record["tag"],
        "name": record["tag"],
        "target_commitish": target,
        "draft": True,
        "prerelease": False,
        "body": body,
        "author": {"login": "github-actions[bot]", "id": 41898282},
        "assets": [
            {
                "name": name,
                "state": "uploaded",
                "size": descriptor["size"],
                "digest": f"sha256:{descriptor['sha256']}",
            }
            for name, descriptor in record["assets"].items()
        ],
    }
    (tmp_path / "record.json").write_text(json.dumps(record), encoding="utf-8")
    (tmp_path / "valid-pages.json").write_text(
        json.dumps([[release]]),
        encoding="utf-8",
    )
    (tmp_path / "malformed-pages.json").write_text("[{}]", encoding="utf-8")
    harness = rf"""
set -euo pipefail
sleep() {{ :; }}
gh() {{
  local attempt
  if test -f gh-count; then
    read -r attempt < gh-count
  else
    attempt=0
  fi
  attempt=$((attempt + 1))
  printf '%s\n' "$attempt" > gh-count
  case "$SCENARIO" in
    absent_then_visible)
      if test "$attempt" -lt 3; then
        printf '[[]]\n'
      else
        cat valid-pages.json
      fi
      ;;
    always_absent)
      printf '[[]]\n'
      ;;
    malformed)
      cat malformed-pages.json
      ;;
    *)
      return 64
      ;;
  esac
}}
cleanup_partial_draft() {{
  local observed_failure=$?
  local failure="${{1:-$observed_failure}}"
  printf 'cleanup:%s\n' "$failure" >> cleanup.log
  exit "$failure"
}}
trap cleanup_partial_draft ERR
record=record.json
body={body!r}
RUNNER_TEMP=.
GITHUB_REPOSITORY=EvoRiseKsa/EvoOM-Guard-m
GITHUB_OUTPUT=github-output
EVOGUARD_PINNED_GH_EXECUTABLE=gh
{retry_loop}
printf 'success:%s\n' "$release_id"
"""

    def invoke(scenario: str) -> subprocess.CompletedProcess[str]:
        for name in ("gh-count", "cleanup.log", "github-output"):
            path = tmp_path / name
            if path.exists():
                path.unlink()
        return subprocess.run(
            [bash, "-s"],
            input=harness,
            text=True,
            capture_output=True,
            cwd=tmp_path,
            env={**os.environ, "SCENARIO": scenario},
            check=False,
            timeout=20,
        )

    eventual = invoke("absent_then_visible")
    assert eventual.returncode == 0, eventual.stdout + eventual.stderr
    assert (tmp_path / "gh-count").read_text(encoding="utf-8").strip() == "3"
    assert not (tmp_path / "cleanup.log").exists()
    assert "success:123" in eventual.stdout

    malformed = invoke("malformed")
    assert malformed.returncode != 0
    assert (tmp_path / "gh-count").read_text(encoding="utf-8").strip() == "1"
    assert (tmp_path / "cleanup.log").read_text(encoding="utf-8").splitlines() == [
        "cleanup:2"
    ]

    timeout = invoke("always_absent")
    assert timeout.returncode != 0
    assert (tmp_path / "gh-count").read_text(encoding="utf-8").strip() == "10"
    assert (tmp_path / "cleanup.log").read_text(encoding="utf-8").splitlines() == [
        "cleanup:1"
    ]


@pytest.mark.parametrize(
    ("scenario", "expected_message", "forbidden_message"),
    (
        (
            "delete_fails",
            "failed to delete the uniquely attributable incomplete draft",
            "removed only the incomplete draft",
        ),
        (
            "delete_gets_404",
            "removed only the incomplete draft created by this H run: 123",
            "draft deletion could not be proven",
        ),
        (
            "delete_gets_500",
            "draft deletion could not be proven by an exact HTTP 404",
            "removed only the incomplete draft",
        ),
        (
            "delete_gets_404_then_500",
            "draft deletion could not be proven by an exact HTTP 404",
            "removed only the incomplete draft",
        ),
    ),
)
def test_h_cleanup_claims_deletion_only_after_exact_404(
    tmp_path: Path,
    scenario: str,
    expected_message: str,
    forbidden_message: str,
) -> None:
    bash = _working_bash()
    if bash is None:
        pytest.skip("a working Bash is required to execute H cleanup")

    run = _h_publication_run()
    start = run.index("cleanup_partial_draft() {")
    end = run.index("\n}\ntrap cleanup_partial_draft ERR", start) + len("\n}")
    cleanup_function = run[start:end]
    harness = rf"""
set -u
sleep() {{ :; }}
python() {{
  cat >/dev/null
  printf '123\n'
}}
gh() {{
  case " $* " in
    *" --method DELETE "*)
      test "$SCENARIO" != delete_fails
      ;;
    *" --include "*)
      if test "$SCENARIO" = delete_gets_404; then
        printf 'HTTP/2.0 404 Not Found\n'
      elif test "$SCENARIO" = delete_gets_404_then_500; then
        printf 'HTTP/2.0 404 Not Found\nHTTP/2.0 500 Internal Server Error\n'
      else
        printf 'HTTP/2.0 500 Internal Server Error\n'
      fi
      return 1
      ;;
    *)
      printf '[[]]\n'
      ;;
  esac
}}
record=record.json
body=deterministic
RUNNER_TEMP=.
GITHUB_REPOSITORY=EvoRiseKsa/EvoOM-Guard-m
EVOGUARD_PINNED_GH_EXECUTABLE=gh
{cleanup_function}
false
cleanup_partial_draft
"""
    completed = subprocess.run(
        [bash, "-s"],
        input=harness,
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env={**os.environ, "SCENARIO": scenario},
        check=False,
        timeout=10,
    )

    assert completed.returncode == 1
    assert expected_message in completed.stderr
    assert forbidden_message not in completed.stderr


def test_h_tag_push_failure_is_visible_and_runs_exact_cleanup(tmp_path: Path) -> None:
    bash = _working_bash()
    if bash is None:
        pytest.skip("a working Bash is required to execute H tag push handling")

    run = next(
        block
        for block in _literal_run_blocks(H)
        if "tag-create-by-deploy-key.txt" in block
    )
    start = run.index('if GIT_SSH_COMMAND="$tag_ssh_command"')
    end = run.index('\nTAG="$tag" python -', start)
    push_block = run[start:end]
    harness = rf"""
set -euo pipefail
git() {{
  printf 'ssh: connect to host github.com port 22: denied\n' >&2
  return 42
}}
cleanup_verified_unpublished_draft() {{
  printf 'cleanup:%s\n' "$1" >&2
  exit "$1"
}}
tag_ssh_command='ssh pinned'
tag_repo=tag.git
tag_remote=git@github.com:EvoRiseKsa/EvoOM-Guard-m.git
TARGET_SHA={'a' * 40}
tag=v4.4.0
RUNNER_TEMP=.
{push_block}
"""
    completed = subprocess.run(
        [bash, "-s"],
        input=harness,
        text=True,
        capture_output=True,
        cwd=tmp_path,
        check=False,
        timeout=10,
    )

    assert completed.returncode == 42
    assert "deploy-key tag push failed before ref proof (exit 42)" in completed.stderr
    assert "ssh: connect to host github.com port 22: denied" in completed.stderr
    assert "cleanup:42" in completed.stderr


@pytest.mark.parametrize(
    ("gh_rc", "http_status", "expected_rc", "cleanup_message"),
    (
        (1, "404", 0, None),
        (0, "200", 1, "cleanup:1"),
        (1, "500", 1, "cleanup:1"),
    ),
)
def test_h_tag_absence_probe_is_err_trap_safe_and_fail_closed(
    tmp_path: Path,
    gh_rc: int,
    http_status: str,
    expected_rc: int,
    cleanup_message: str | None,
) -> None:
    bash = _working_bash()
    if bash is None:
        pytest.skip("a working Bash is required to execute H tag absence handling")

    run = next(
        block
        for block in _literal_run_blocks(H)
        if "tag-before-publication.response" in block
    )
    start = run.index(
        'if "$EVOGUARD_PINNED_GH_EXECUTABLE" api --include '
        '"repos/$GITHUB_REPOSITORY/git/ref/tags/$tag"'
    )
    end = run.index("\nRELEASE_BODY=", start)
    probe_block = run[start:end]
    harness = rf"""
set -Eeuo pipefail
gh() {{
  printf 'HTTP/2.0 %s result\n' "$HTTP_STATUS"
  return "$GH_RC"
}}
cleanup_verified_unpublished_draft() {{
  printf 'cleanup:%s\n' "$1" >&2
  exit "$1"
}}
trap cleanup_verified_unpublished_draft ERR
GITHUB_REPOSITORY=EvoRiseKsa/EvoOM-Guard-m
tag=v4.4.0
RUNNER_TEMP=.
EVOGUARD_PINNED_GH_EXECUTABLE=gh
{probe_block}
printf 'probe:%s:%s\n' "$tag_probe_rc" "$tag_status"
"""
    completed = subprocess.run(
        [bash, "-s"],
        input=harness,
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env={
            **os.environ,
            "GH_RC": str(gh_rc),
            "HTTP_STATUS": http_status,
        },
        check=False,
        timeout=10,
    )

    assert completed.returncode == expected_rc
    if cleanup_message is None:
        assert completed.stdout.strip() == f"probe:{gh_rc}:{http_status}"
        assert "cleanup:" not in completed.stderr
    else:
        assert cleanup_message in completed.stderr


@pytest.mark.parametrize(
    ("invocation", "expected_rc", "expected_message"),
    (
        ("cleanup_verified_unpublished_draft 42", 42, "failure:42"),
        ("trap cleanup_verified_unpublished_draft ERR\nfalse", 1, "failure:1"),
    ),
)
def test_h_exact_cleanup_preserves_explicit_and_trapped_failure_status(
    tmp_path: Path,
    invocation: str,
    expected_rc: int,
    expected_message: str,
) -> None:
    bash = _working_bash()
    if bash is None:
        pytest.skip("a working Bash is required to execute H cleanup status handling")

    run = next(
        block
        for block in _literal_run_blocks(H)
        if "tag-before-publication.response" in block
    )
    start = run.index("cleanup_verified_unpublished_draft() {")
    end = run.index("local release_ok=", start)
    cleanup_prologue = run[start:end]
    harness = rf"""
set -Euo pipefail
{cleanup_prologue}
printf 'failure:%s\n' "$failure" >&2
exit "$failure"
}}
false
{invocation}
"""
    completed = subprocess.run(
        [bash, "-s"],
        input=harness,
        text=True,
        capture_output=True,
        cwd=tmp_path,
        check=False,
        timeout=10,
    )

    assert completed.returncode == expected_rc
    assert expected_message in completed.stderr


def test_historical_direct_release_path_is_hard_disabled() -> None:
    for name in (
        "validate-test",
        "release-e2e",
        "release-windows-e2e",
        "build-artifact",
        "attest-release-assets",
        "prepare-draft",
    ):
        block = _job(LEGACY, name)
        assert "if: false && github.ref ==" in block
