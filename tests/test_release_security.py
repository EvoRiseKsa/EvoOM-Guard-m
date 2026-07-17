"""Supply-chain invariants for release workflows."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
WINDOWS = ROOT / ".github" / "workflows" / "windows.yml"
WORKFLOWS = ROOT / ".github" / "workflows"


def _job_block(workflow: Path, job_name: str) -> str:
    text = workflow.read_text(encoding="utf-8")
    match = re.search(
        rf"^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"missing job: {workflow.name}:{job_name}"
    return match.group(0)


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
    assert "vitest@4.1.10" in release_windows
    assert "test_vitest_oracle.py" in release_windows
    ci_windows = _job_block(WINDOWS, "smoke")
    assert "runs-on: windows-latest" in ci_windows
    assert "persist-credentials: false" in ci_windows
    assert "vitest@4.1.10" in ci_windows
    assert "python -m pytest tests/ -q" in ci_windows
    assert "contents: read" in build
    assert "attestations: write" in build
    assert "id-token: write" in build
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

    assert "needs: [validate-test, build-artifact]" in prepare
    assert "contents: write" in prepare
    assert (
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
        in prepare
    )
    assert "name: release-assets" in prepare
    assert "github.run_attempt" not in prepare
    assert "actions/checkout@" not in prepare
    assert "pip install" not in prepare
    assert "pytest" not in prepare
    assert "ruff " not in prepare
    assert "mypy " not in prepare
    assert "ops/build_pyz.py" not in prepare
    assert "python dist/evo-guard.pyz" not in prepare
    assert "release_checksum_format_invalid" in prepare
    assert "'^[0-9a-f]{64}  evo-guard\\.pyz$'" in prepare


def test_future_release_artifact_is_attested_before_crossing_job_boundary() -> None:
    build = _job_block(RELEASE, "build-artifact")
    attestation_action = "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"
    assert attestation_action in build
    assert "subject-path: dist/evo-guard.pyz" in build
    assert "Generate GitHub build provenance for the exact artifact" in build
    assert build.index("Checksums (release integrity)") < build.index(attestation_action)
    assert build.index(attestation_action) < build.index("Transfer the verified release assets")


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
    assert "ruff check evoom_guard/ tests/" in text
    assert "mypy evoom_guard/" in text
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
    assert "SHA256SUMS evo-guard.pyz" in text


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
