"""Supply-chain invariants for release workflows."""

import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).parents[1]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
WINDOWS = ROOT / ".github" / "workflows" / "windows.yml"
WORKFLOWS = ROOT / ".github" / "workflows"


def test_every_checkout_discards_persisted_credentials() -> None:
    """No later step should inherit checkout's repository credential helper."""

    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        lines = workflow.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if "uses: actions/checkout@" not in line:
                continue
            checkout_indent = len(line) - len(line.lstrip())
            step_lines: list[str] = []
            for following in lines[index + 1 :]:
                following_indent = len(following) - len(following.lstrip())
                if (
                    following.strip().startswith("- ")
                    and following_indent <= checkout_indent
                ):
                    break
                step_lines.append(following)
            assert any(
                item.strip() == "persist-credentials: false"
                for item in step_lines
            ), f"{workflow.name}:{index + 1} persists checkout credentials"


def _job_block(workflow: Path, job_name: str) -> str:
    text = workflow.read_text(encoding="utf-8")
    match = re.search(
        rf"^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"missing job: {workflow.name}:{job_name}"
    return match.group(0)


def _clean_attestation_verifier_script() -> str:
    block = _job_block(RELEASE, "attest-release-assets")
    marker = 'EXPECTED_VERSION="${TAG#v}" python3 -I - <<\'PY\'\n'
    assert marker in block
    script_with_tail = block.split(marker, maxsplit=1)[1]
    script, separator, _tail = script_with_tail.partition("\n          PY\n")
    assert separator
    return textwrap.dedent(script)


def test_release_assets_are_immutable_and_bound_to_the_tag_commit() -> None:
    for workflow in (RELEASE, CI):
        text = workflow.read_text(encoding="utf-8")
        assert "--clobber" not in text
        assert "release_tag_target_mismatch" in text
        assert "release_asset_immutable" in text
        assert "commits/$" in text
        assert "cmp -s" in text


def test_absent_release_tag_does_not_capture_api_error_json_as_a_sha() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    assert 'git/ref/tags/$TAG' in text
    assert '--jq .sha 2>/dev/null || true' not in text
    assert 'TAG_SHA=""' in text
    assert "TAG_REF_STATUS=$?" in text
    assert "release_tag_lookup_failed" in text
    assert "'^HTTP/[^ ]+ 404 '" in text


def test_dispatch_tag_is_data_not_inline_shell_and_is_validated_before_output() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    validate = _job_block(RELEASE, "validate-test")
    assert "DISPATCH_TAG: ${{ inputs.tag }}" in validate
    assert 'TAG="${{ inputs.tag }}"' not in text
    canonical_check = (
        '[[ ! "$TAG" =~ ^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)'
        '\\.(0|[1-9][0-9]*)$ ]]'
    )
    assert canonical_check in validate
    check_at = validate.index(canonical_check)
    assert check_at < validate.index("$GITHUB_OUTPUT")
    assert check_at < validate.index("$GITHUB_ENV")


def test_release_validation_build_and_write_privileges_are_separated() -> None:
    validate = _job_block(RELEASE, "validate-test")
    build = _job_block(RELEASE, "build-artifact")
    attest = _job_block(RELEASE, "attest-release-assets")
    prepare = _job_block(RELEASE, "prepare-draft")

    assert "contents: read" in validate
    assert "persist-credentials: false" in validate
    assert "pip install" in validate

    assert "needs: [validate-test, release-e2e, release-windows-e2e]" in build
    release_e2e = _job_block(RELEASE, "release-e2e")
    assert "contents: read" in release_e2e
    assert "test_vitest_oracle.py" in release_e2e
    assert "test_blackbox_docker_e2e.py" in release_e2e
    release_windows = _job_block(RELEASE, "release-windows-e2e")
    assert "runs-on: windows-latest" in release_windows
    assert "contents: read" in release_windows
    assert "npm ci --ignore-scripts --prefix tools/ci-vitest" in release_windows
    assert "npm install -g" not in release_windows
    assert "test_vitest_oracle.py" in release_windows
    ci_windows = _job_block(WINDOWS, "smoke")
    assert "runs-on: windows-latest" in ci_windows
    assert "persist-credentials: false" in ci_windows
    assert "fetch-depth: 0" in ci_windows
    assert "npm ci --ignore-scripts --prefix tools/ci-vitest" in ci_windows
    assert "npm install -g" not in ci_windows
    assert "python -m pytest tests/ -q" in ci_windows
    assert "contents: read" in build
    assert "attestations: write" not in build
    assert "id-token: write" not in build
    assert "contents: write" not in build
    assert "persist-credentials: false" in build
    assert (
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        in build
    )
    assert "name: release-assets" in build
    assert "overwrite: true" in build
    assert "github.run_attempt" not in build
    assert "pip install" not in build
    assert "pytest" not in build
    assert "ruff " not in build
    assert "mypy " not in build
    assert "python -I ops/build_pyz.py" in build
    assert "python -I dist/evo-guard.pyz" in build

    assert "needs: [validate-test, build-artifact]" in attest
    assert "attestations: write" in attest
    assert "id-token: write" in attest
    assert "contents: read" in attest
    assert "contents: write" not in attest
    assert "actions/checkout@" not in attest
    assert "actions/setup-python@" not in attest
    assert "pip install" not in attest
    assert "pytest" not in attest
    assert "ops/build_pyz.py" not in attest
    assert "ops/generate_spdx_sbom.py" not in attest
    assert "python3 -I - <<'PY'" in attest
    assert "dist/evo-guard.pyz version" not in attest
    assert "dist/evo-guard.pyz doctor" not in attest
    assert "sbom_subject_digest_mismatch" in attest
    assert "SPDXRef-Package-evoom-guard" in attest
    assert "artifact-ids: ${{ needs.build-artifact.outputs.release-artifact-id }}" in attest
    assert "digest-mismatch: error" in attest
    assert "steps.upload-release-assets.outputs.artifact-id" in build
    assert "steps.upload-release-assets.outputs.artifact-digest" in build
    assert "steps.approve-artifact.outputs.artifact-id" in attest
    assert "steps.approve-artifact.outputs.artifact-digest" in attest
    assert "'artifact-id=%s\\n'" in attest
    assert "'artifact-digest=%s\\n'" in attest
    assert '[[ "$ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]]' in attest
    assert '[[ "$ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]]' in prepare
    assert "SBOM_BYTES\" -gt 16777216" in attest
    assert "object_pairs_hook=unique_object" in attest
    assert '"versionInfo": os.environ["EXPECTED_VERSION"]' in attest

    assert "needs: [validate-test, attest-release-assets]" in prepare
    assert "contents: write" in prepare
    assert (
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
        in prepare
    )
    assert (
        "artifact-ids: "
        "${{ needs.attest-release-assets.outputs.approved-artifact-id }}"
        in prepare
    )
    assert "digest-mismatch: error" in prepare
    assert (
        "needs.attest-release-assets.outputs.approved-artifact-digest"
        in prepare
    )
    assert "github.run_attempt" not in prepare
    assert "actions/checkout@" not in prepare
    assert "pip install" not in prepare
    assert "pytest" not in prepare
    assert "ruff " not in prepare
    assert "mypy " not in prepare
    assert "ops/build_pyz.py" not in prepare
    assert "ops/generate_spdx_sbom.py" not in prepare
    assert "python dist/evo-guard.pyz" not in prepare
    assert "release_checksum_format_invalid" in prepare
    assert "'^[0-9a-f]{64}  evo-guard\\.pyz$'" in prepare
    assert "'^[0-9a-f]{64}  evo-guard\\.spdx\\.json$'" in prepare
    assert "find dist -mindepth 1 -maxdepth 1" in prepare
    assert "-printf '%y\\t%f\\n'" in prepare


def test_future_release_artifact_and_sbom_are_attested_in_a_clean_job() -> None:
    build = _job_block(RELEASE, "build-artifact")
    attest = _job_block(RELEASE, "attest-release-assets")
    attestation_action = "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"
    assert attestation_action not in build
    assert attest.count(attestation_action) == 2
    assert attest.count("subject-path: dist/evo-guard.pyz") == 2
    assert "sbom-path: dist/evo-guard.spdx.json" in attest
    assert "Generate GitHub build provenance for the exact artifact" in attest
    assert "Generate GitHub SBOM attestation for the exact artifact" in attest
    receive_at = attest.index("Receive the generated release assets")
    bind_at = attest.index("Bind the transferred SBOM")
    provenance_at = attest.index("Generate GitHub build provenance")
    sbom_at = attest.index("Generate GitHub SBOM attestation")
    assert receive_at < bind_at < provenance_at < sbom_at


def test_clean_attestation_verifier_executes_positive_and_negative_cases(
    tmp_path: Path,
) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    pyz = dist / "evo-guard.pyz"
    pyz.write_bytes(b"exact-release-bytes")
    digest = hashlib.sha256(pyz.read_bytes()).hexdigest()
    script = _clean_attestation_verifier_script()
    environment = {**os.environ, "EXPECTED_VERSION": "4.4.0"}

    def package() -> dict[str, object]:
        return {
            "SPDXID": "SPDXRef-Package-evoom-guard",
            "name": "evo-guard",
            "packageFileName": "evo-guard.pyz",
            "versionInfo": "4.4.0",
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": "0" * 40},
                {"algorithm": "SHA256", "checksumValue": digest},
            ],
        }

    def run(document: str | dict[str, object]) -> subprocess.CompletedProcess[str]:
        rendered = document if isinstance(document, str) else json.dumps(document)
        (dist / "evo-guard.spdx.json").write_text(rendered, encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    assert run({"packages": [package()]}).returncode == 0

    duplicate = json.dumps({"packages": [package()]})
    duplicate = duplicate[:-1] + ',"packages":[]}'
    invalid_documents: list[str | dict[str, object]] = [duplicate]

    wrong_version = package()
    wrong_version["versionInfo"] = "4.4.1"
    invalid_documents.append({"packages": [wrong_version]})

    wrong_filename = package()
    wrong_filename["packageFileName"] = "other.pyz"
    invalid_documents.append({"packages": [wrong_filename]})

    invalid_documents.append({"packages": [package(), package()]})

    wrong_digest = package()
    wrong_digest["checksums"] = [
        {"algorithm": "SHA256", "checksumValue": "f" * 64}
    ]
    invalid_documents.append({"packages": [wrong_digest]})

    for document in invalid_documents:
        assert run(document).returncode != 0


def test_future_release_asset_contract_is_exact_and_filename_ordered() -> None:
    build = _job_block(RELEASE, "build-artifact")
    prepare = _job_block(RELEASE, "prepare-draft")
    publish = _job_block(CI, "publish-pyz")
    assert "python -I ops/generate_spdx_sbom.py" in build
    assert "python -I ops/generate_spdx_sbom.py" in publish
    assert "--version \"${TAG#v}\"" in build
    assert "--version \"${GITHUB_REF_NAME#v}\"" in publish
    for block in (build, prepare, publish):
        assert "evo-guard.pyz" in block
        assert "evo-guard.spdx.json" in block
        assert "SHA256SUMS" in block
    for block in (build, publish):
        checksum = "sha256sum evo-guard.pyz evo-guard.spdx.json > SHA256SUMS"
        assert checksum in block
    for block in (prepare, publish):
        assert "find dist -mindepth 1 -maxdepth 1" in block
        assert "-printf '%y\\t%f\\n'" in block
        assert "release_checksum_format_invalid" in block


def test_release_is_manual_and_accepts_only_the_default_branch() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "\n  push:" not in text
    assert "release/v" not in text
    assert "permissions: {}" in text
    default_branch_guard = (
        "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
    )
    for job in (
        "validate-test",
        "release-e2e",
        "release-windows-e2e",
        "build-artifact",
        "attest-release-assets",
        "prepare-draft",
    ):
        assert default_branch_guard in _job_block(RELEASE, job)


def test_non_release_workflows_declare_their_read_only_baseline() -> None:
    for workflow in (CI, WINDOWS):
        text = workflow.read_text(encoding="utf-8")
        assert "permissions:\n  contents: read" in text

    codeql = (WORKFLOWS / "codeql.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in codeql
    analyze = _job_block(WORKFLOWS / "codeql.yml", "analyze")
    assert "security-events: write" in analyze


def test_extracted_contracts_have_strict_type_gates() -> None:
    for workflow in (CI, RELEASE):
        text = workflow.read_text(encoding="utf-8")
        assert "python -m mypy --strict evoom_guard/domain/" in text
        assert "python -m mypy --strict evoom_guard/candidate/" in text
        assert "python -m mypy --strict evoom_guard/workspace/" in text
        assert "python -m mypy --strict evoom_guard/policy/" in text


def test_release_workflow_prepares_a_draft_and_never_publishes_it() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    create = re.search(
        r'gh release create "\$TAG"(?P<args>.*?)(?:\n\s*fi\n)',
        text,
        flags=re.DOTALL,
    )
    assert create is not None
    assert "--draft" in create.group("args")
    assert '--target "$GITHUB_SHA"' in create.group("args")
    assert "assets,isDraft,isImmutable,tagName,targetCommitish" in text
    assert "release_target_commit_mismatch" in text
    assert "gh release edit" not in text
    assert "--draft=false" not in text
    assert "--draft false" not in text
    assert "ruff check" in text
    assert "ops/build_pyz.py ops/generate_spdx_sbom.py" in text
    assert "mypy evoom_guard/" in text
    assert "mypy --strict" in text
    assert "python -m pytest tests/ -q" in text
    assert 'default: "v2.0.0"' not in text


def test_release_rerun_only_uploads_missing_assets_to_a_draft() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    assert 'if [ "$RELEASE_IS_DRAFT" != "true" ]' in text
    assert "published release is missing $asset" in text
    assert 'gh release upload "$TAG" "dist/$asset"' in text
    assert 'cmp -s "dist/$asset" "existing-release-assets/$asset"' in text
    assert "unexpected existing assets" in text
    assert "final release asset set is not exact" in text
    assert "SHA256SUMS evo-guard.pyz evo-guard.spdx.json" in text
    assert "for asset in evo-guard.pyz evo-guard.spdx.json SHA256SUMS" in text


def test_tag_ci_only_verifies_published_assets_read_only() -> None:
    publish_job = _job_block(CI, "publish-pyz")
    assert "contents: read" in publish_job
    assert "persist-credentials: false" in publish_job
    assert "gh release create" not in publish_job
    assert "gh release upload" not in publish_job
    assert "published release is missing $asset" in publish_job
    assert 'cmp -s "dist/$asset" "existing-release-assets/$asset"' in publish_job
    assert "assets,isDraft,isImmutable,tagName,targetCommitish" in publish_job
    assert '"$RELEASE_IS_DRAFT" != "false"' in publish_job
    assert '"$RELEASE_IS_IMMUTABLE" != "true"' in publish_job
    assert "published release asset set is not exact" in publish_job
    assert "evo-guard.spdx.json" in publish_job
    assert "for asset in evo-guard.pyz evo-guard.spdx.json SHA256SUMS" in publish_job


def test_all_workflow_actions_are_pinned_to_commit_shas() -> None:
    seen: list[str] = []
    for workflow in sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml"))):
        text = workflow.read_text(encoding="utf-8")
        uses = re.findall(
            r"^\s*(?:-\s+)?uses:\s*([^\s#]+)", text, flags=re.MULTILINE
        )
        for target in uses:
            seen.append(f"{workflow.name}: {target}")
            assert target.startswith("./") or re.fullmatch(
                r"[^@]+@[0-9a-f]{40}", target
            ), f"mutable action reference: {workflow.name}: {target}"
    assert seen
