# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Static trust-boundary contracts for the inert A-H release pipeline."""

from __future__ import annotations

import json
import re
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


def test_release_workflow_python_heredocs_are_exact_and_compile() -> None:
    count = 0
    for path in (F, G, H):
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
                compile(
                    "\n".join(source) + "\n",
                    f"{path.name}:run:{block_index}",
                    "exec",
                )
                count += 1
                index = end + 1
    assert count == 33


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
    assert bootstrap["post_publication_evidence"]["first_ledger"] == "v4.4.0"
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
        "benchmarks/results.jsonl",
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
    assert "evidence/release-ledgers/*" in policy["protected"]
    assert "security/release-ledger-roots/*" in policy["protected"]
    assert "security/release-source-pack/*" in policy["protected"]
    assert "security/release-pipeline-bootstrap.json" in policy["protected"]
    ledger_root = ROOT / "security/release-ledger-roots/v4.4.0.pub.pem"
    assert ledger_root.is_file()
    assert (
        public_key_id(str(ledger_root))
        == "sha256:20cc7a937e94b716dd14642dc668ef365e0d74af11c84009237e7fe847df6e0f"
    )
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
                "security/release-ledger-roots/v4.4.0.pub.pem",
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
        "security/release-ledger-roots/v4.4.0.pub.pem",
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
        version_assignment='__version__ = "4.4.0.dev0"',
    )
    _write_scope_tree(
        candidate,
        version_assignment='__version__ = "4.4.0"',
        readme="candidate\n",
    )

    assert candidate_scope.validate_candidate_scope(base, candidate) == (
        "README.md",
        "evoom_guard/__init__.py",
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
        version_assignment='__version__ = "4.4.0.dev0"',
        guard="VALUE = 1\n",
    )
    _write_scope_tree(
        candidate,
        version_assignment='__version__ = "4.4.0"',
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
        version_assignment='__version__ = "4.4.0.dev0"',
        guard="VALUE = 1\n",
    )
    _write_scope_tree(
        candidate,
        version_assignment='__version__ = "4.4.0"',
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
        version_assignment='__version__ = "4.4.0.dev0"',
    )
    _write_scope_tree(
        candidate,
        version_assignment='__version__ = "4.4.0"',
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
        '# frozen prefix\n__version__ = "4.4.0"\n# changed suffix\n',
        '# frozen prefix\n__version__ = "4.4.1"\n# frozen suffix\n',
        (
            '# frozen prefix\n__version__ = "4.4.0"\n'
            'SECOND_VERSION = "4.4.0"\n# frozen suffix\n'
        ),
        (
            "# frozen prefix\n"
            'import os\n__version__ = "4.4.0"\n# frozen suffix\n'
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
        version_assignment='__version__ = "4.4.0.dev0"',
    )
    _write_scope_tree(
        candidate,
        version_assignment='__version__ = "4.4.0"',
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

    assert "attestations: write" in attest
    assert "id-token: write" in attest
    assert "actions/checkout@" not in attest
    assert "python -I admitted-source/ops/build_pyz.py" not in attest
    assert "python -I /trusted-tools/build_pyz.py" not in attest
    assert "python -I /trusted-tools/generate_spdx_sbom.py" not in attest
    assert "docker run" not in attest
    assert "python -I ${{ runner.temp }}/e-output/evo-guard.pyz" not in attest
    assert attest.count(
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"
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
    assert "'version': '4.3.0'" in preflight
    assert ".external_settings.runtime.version" in attestations
    assert "evo-guard $RUNTIME_VERSION" in attestations
    assert "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_PRIVATE_KEY_B64" not in attestations
    assert "evoguard-release-artifact-v1-complete-controls-" in attestations
    assert "complete F control inventory" not in attestations
    assert "find \"$RUNNER_TEMP/f-controls-complete\"" in attestations

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


def test_h_reverifies_then_writes_only_an_exact_draft() -> None:
    preflight = _job(H, "preflight")
    draft = _job(H, "draft")
    publish = _job(H, "publish")
    whole = _text(H)

    assert "EVOGUARD_RELEASE_PUBLICATION_ENABLED == 'true'" in preflight
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
    assert "immutable-releases" in draft
    assert "immutable-releases" in publish
    assert '"X-GitHub-Api-Version: 2026-03-10"' in whole
    assert "--method PATCH" in publish
    assert '{"draft":false}' in publish
    assert "release.get('immutable') is not True" in publish
    assert "published tag does not bind the admitted target" in publish
    assert "for attempt in {1..10}" in publish
    assert "sleep 2" in publish
    assert "gh release create" in publish
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
    assert "git -C \"$tag_repo\" push" in publish
    assert '"$TARGET_SHA:refs/tags/$tag"' in publish
    assert '":refs/tags/$tag"' in publish
    assert '--force-with-lease="refs/tags/$tag:$TARGET_SHA"' in publish
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
        "trap - ERR\n          gh api"
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
