"""Supply-chain invariants for release workflows."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
PUBLISHED_VERIFY = ROOT / ".github" / "workflows" / "release-published-verify.yml"
WINDOWS = ROOT / ".github" / "workflows" / "windows.yml"
WORKFLOWS = ROOT / ".github" / "workflows"
MAINTAINER_ROOT = ROOT / "security" / "release-maintainer-roots" / "v4.7.0.json"
MAINTAINER_KEY = ROOT / "security" / "release-maintainer-roots" / "v4.7.0.pub"
FAILED_V470_ATTEMPT = (
    ROOT
    / "evidence"
    / "release-attempts"
    / "v4.7.0"
    / "FAILED_DRAFT_ATTEMPT.json"
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_failed_v470_attempt(raw: str) -> dict[str, object]:
    value = json.loads(
        raw,
        object_pairs_hook=_unique_object,
        parse_constant=lambda constant: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON constant: {constant}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError("failed release attempt root is not an object")
    return value


def test_failed_v470_attempt_is_bounded_and_v471_is_the_successor() -> None:
    raw = FAILED_V470_ATTEMPT.read_text(encoding="utf-8")
    assert "\r" not in raw
    assert raw.endswith("\n")
    record = _load_failed_v470_attempt(raw)
    assert raw == json.dumps(
        record,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
    ) + "\n"
    assert set(record) == {
        "format",
        "version",
        "status",
        "observed_utc",
        "repository",
        "source",
        "tag",
        "workflow_run",
        "draft_release",
        "root_cause",
        "corrective_action",
        "cleanup",
        "claims",
    }
    assert record["format"] == "EVOGUARD_FAILED_RELEASE_ATTEMPT_V1"
    assert record["version"] == "v4.7.0"
    assert record["status"] == "WITHDRAWN_UNPUBLISHED_DRAFT_ATTEMPT"
    assert record["observed_utc"] == "2026-09-01T11:06:32Z"
    assert record["repository"] == "EvoRiseKsa/EvoOM-Guard-m"
    assert record["source"] == {
        "commit_sha": "06c3fd7744a22b94a194124731046241fa219db3",
        "tree_sha": "0eeb4fbe5d49a152a9afdb572f088e06a7e15558",
    }
    tag = record["tag"]
    assert isinstance(tag, dict)
    assert tag == {
        "name": "v4.7.0",
        "object_sha": "026d9f86e167efe7728c4fd5feb89cc9b6a0ad7c",
        "target_commit_sha": "06c3fd7744a22b94a194124731046241fa219db3",
        "github_verification": {
            "verified": True,
            "reason": "valid",
            "verified_at": "2026-09-01T10:11:51Z",
        },
        "disposition": "PRESERVED_UNCHANGED_NOT_A_CONSUMER_RELEASE",
    }
    workflow = record["workflow_run"]
    assert isinstance(workflow, dict)
    assert set(workflow) == {
        "id",
        "attempt",
        "event",
        "actor",
        "head_sha",
        "created_at",
        "updated_at",
        "conclusion",
        "prepare_draft_job",
        "publish_release_job",
        "postpublication_verifier_job",
        "provider_timestamp_anomaly",
        "publication_mutation_started",
    }
    assert workflow["id"] == 33498177503
    assert workflow["attempt"] == 1
    assert workflow["event"] == "workflow_dispatch"
    assert workflow["actor"] == "EvoRiseKsa"
    assert workflow["head_sha"] == record["source"]["commit_sha"]
    assert workflow["created_at"] == "2026-09-01T10:35:17Z"
    assert workflow["updated_at"] == "2026-09-01T10:47:48Z"
    assert workflow["conclusion"] == "failure"
    assert workflow["prepare_draft_job"] == {
        "id": 99827881565,
        "failed_step_number": 6,
        "failed_step_name": "Prepare the draft release and immutable asset set",
        "failure": "GH_RELEASE_DOWNLOAD_BY_TAG_RETURNED_HTTP_404_FOR_DRAFT",
    }
    for job_name, job_id in (
        ("publish_release_job", 99828411652),
        ("postpublication_verifier_job", 99828411734),
    ):
        job = workflow[job_name]
        assert isinstance(job, dict)
        assert job == {
            "id": job_id,
            "conclusion": "skipped",
            "started_at": "2026-09-01T10:47:48Z",
            "completed_at": "2026-09-01T10:47:47Z",
        }
    assert workflow["provider_timestamp_anomaly"] == (
        "SKIPPED_JOB_STARTED_AT_AFTER_COMPLETED_AT_NO_TEMPORAL_ORDER_CLAIM"
    )
    assert workflow["publication_mutation_started"] is False
    assert record["claims"] == {
        "consumer_release_created": False,
        "publication_authorized": False,
        "independent_validation": False,
    }
    draft = record["draft_release"]
    assert isinstance(draft, dict)
    assert set(draft) == {
        "id",
        "tag_name",
        "name",
        "target_commitish",
        "draft",
        "prerelease",
        "immutable",
        "published_at",
        "author",
        "canonical_body_sha256",
        "raw_api_snapshot",
        "assets",
    }
    assert {
        key: draft[key]
        for key in (
            "id",
            "tag_name",
            "name",
            "target_commitish",
            "draft",
            "prerelease",
            "immutable",
            "published_at",
            "author",
        )
    } == {
        "id": 380414798,
        "tag_name": "v4.7.0",
        "name": "v4.7.0",
        "target_commitish": record["source"]["commit_sha"],
        "draft": True,
        "prerelease": False,
        "immutable": False,
        "published_at": None,
        "author": {"login": "github-actions[bot]", "id": 41898282},
    }
    assert draft["canonical_body_sha256"] == (
        "981b8128c58d059fc94aff4441633412acae6fc6fd7c0596a1266e5e827b4e85"
    )
    assert draft["raw_api_snapshot"] == {
        "sha256": "bdd35c076e85e129da486bc613c9478f457765bc90fdbcff096a95b2832cc2e8",
        "bytes": 12238,
        "raw_bytes_retained": False,
    }
    assert draft["assets"] == [
        {
            "id": 539407115,
            "name": "evo-guard.pyz",
            "size": 2986078,
            "digest": (
                "sha256:cf58bd26e9facaa0fd14c2b4812c962e"
                "a051ca6b6b54c9065d0ce98a2ccf6ad0"
            ),
            "state": "uploaded",
            "label": "",
            "content_type": "application/octet-stream",
            "uploader_login": "github-actions[bot]",
            "uploader_id": 41898282,
            "uploader_type": "Bot",
        },
        {
            "id": 539407160,
            "name": "evo-guard.spdx.json",
            "size": 130832,
            "digest": (
                "sha256:2a96c4fc2b10dbe6a02a3294226bfc51"
                "b0656b47f96c333b5695119e87616114"
            ),
            "state": "uploaded",
            "label": "",
            "content_type": "application/json",
            "uploader_login": "github-actions[bot]",
            "uploader_id": 41898282,
            "uploader_type": "Bot",
        },
        {
            "id": 539407180,
            "name": "SHA256SUMS",
            "size": 166,
            "digest": (
                "sha256:d3a5388c0153cf5e00ef3d2b75a56dcb"
                "5054a565717e37d9eaab9cbd807f1a6e"
            ),
            "state": "uploaded",
            "label": "",
            "content_type": "application/octet-stream",
            "uploader_login": "github-actions[bot]",
            "uploader_id": 41898282,
            "uploader_type": "Bot",
        },
    ]
    assert record["root_cause"] == (
        "The workflow used tag-based release resolution while the release was "
        "still a draft. The immediate gh release download returned HTTP 404, "
        "the later published-release-by-tag REST lookup would also have "
        "returned 404, and a retry could have created a duplicate hidden draft."
    )
    assert record["corrective_action"] == (
        "Release v4.7.1 uses paginated unique draft discovery, numeric release "
        "and asset IDs before publication, and a by-tag identity join only "
        "after immutable publication."
    )
    cleanup = record["cleanup"]
    assert cleanup == {
        "draft_release_id": 380414798,
        "status": "VERIFIED_DELETED_TAG_PRESERVED",
        "public_branch_capture": {
            "commit_sha": "8e2a518ecaee611897871a6abec1b9584c8f3a7b",
            "evidence_blob_sha": "670c78549de31f190d9c00d9bf7b9ce3c9f8087d",
            "evidence_sha256": (
                "e6cb5ed59a8bd29364b956dad56fed7236b3722726fff9567d44c582901281b1"
            ),
            "evidence_bytes": 4384,
        },
        "delete_method": "REST_DELETE_NUMERIC_RELEASE_ID_ONLY",
        "delete_actor": "MANA-awam",
        "delete_observed_github_server_utc": "2026-09-01T11:50:14Z",
        "release_get_http_after_delete": 404,
        "release_tag_matches_after_delete": 0,
        "tag_object_sha_after_delete": (
            "026d9f86e167efe7728c4fd5feb89cc9b6a0ad7c"
        ),
        "tag_target_commit_sha_after_delete": (
            "06c3fd7744a22b94a194124731046241fa219db3"
        ),
        "tag_github_verification_after_delete": {
            "verified": True,
            "reason": "valid",
        },
        "main_commit_sha_after_delete": (
            "06c3fd7744a22b94a194124731046241fa219db3"
        ),
        "deploy_keys_after_delete": 0,
        "tag_delete_forbidden": True,
        "same_owner_operation": True,
        "independent_validation": False,
    }
    assert '__version__ = "4.7.1"' in (
        ROOT / "evoom_guard" / "__init__.py"
    ).read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [4.7.1] — 2026-09-01" in changelog
    assert "## [4.7.0] — 2026-08-31 (unpublished; withdrawn)" in changelog


def test_failed_v470_attempt_rejects_duplicate_keys_and_nonfinite_values() -> None:
    raw = FAILED_V470_ATTEMPT.read_text(encoding="utf-8")
    duplicate = raw.replace(
        '  "format": "EVOGUARD_FAILED_RELEASE_ATTEMPT_V1",',
        '  "format": "EVOGUARD_FAILED_RELEASE_ATTEMPT_V1",\n'
        '  "format": "FORGED",',
        1,
    )
    with pytest.raises(ValueError, match="duplicate JSON key: format"):
        _load_failed_v470_attempt(duplicate)
    nonfinite = raw.replace('    "attempt": 1,', '    "attempt": NaN,', 1)
    with pytest.raises(ValueError, match="non-finite JSON constant"):
        _load_failed_v470_attempt(nonfinite)


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


def _prepare_draft_numeric_api_functions() -> str:
    block = _job_block(RELEASE, "prepare-draft")
    start_marker = "          release_api() {\n"
    end_marker = "          upload_release_asset() {\n"
    assert start_marker in block
    assert end_marker in block
    functions = block[block.index(start_marker) : block.index(end_marker)]
    return textwrap.dedent(functions)


def _prepare_draft_create_or_select_script() -> str:
    block = _job_block(RELEASE, "prepare-draft")
    start_marker = "          # A rerun must never create a second hidden draft."
    end_marker = '          [[ "$RELEASE_ID" =~ ^[1-9][0-9]*$ ]]\n'
    assert start_marker in block
    assert end_marker in block
    start = block.index(start_marker)
    end = block.index(end_marker, start) + len(end_marker)
    return textwrap.dedent(block[start:end])


def _prepare_draft_upload_function() -> str:
    block = _job_block(RELEASE, "prepare-draft")
    start_marker = "          upload_release_asset() {\n"
    end_marker = "          # A rerun must never create a second hidden draft."
    assert start_marker in block
    assert end_marker in block
    function = block[block.index(start_marker) : block.index(end_marker)]
    return textwrap.dedent(function)


def _clean_attestation_verifier_script() -> str:
    block = _job_block(RELEASE, "attest-release-assets")
    marker = 'EXPECTED_VERSION="${TAG#v}" python3 -I - <<\'PY\'\n'
    assert marker in block
    script_with_tail = block.split(marker, maxsplit=1)[1]
    script, separator, _tail = script_with_tail.partition("\n          PY\n")
    assert separator
    return textwrap.dedent(script)


def _publication_snapshot_validator_script() -> str:
    block = _job_block(RELEASE, "publish-release")
    marker = '"$snapshot" "$EXPECTED_ASSETS" <<\'PY\'\n'
    assert marker in block
    script_with_tail = block.split(marker, maxsplit=1)[1]
    script, separator, _tail = script_with_tail.partition("\n          PY\n")
    assert separator
    return textwrap.dedent(script)


def _postpublication_snapshot_validator_script() -> str:
    block = _job_block(PUBLISHED_VERIFY, "verify-published-release")
    marker = 'python -I - "$RUNNER_TEMP/release.json" <<\'PY\'\n'
    assert marker in block
    script_with_tail = block.split(marker, maxsplit=1)[1]
    script, separator, _tail = script_with_tail.partition("\n          PY\n")
    assert separator
    return textwrap.dedent(script)


def _postpublication_input_validator_script() -> str:
    text = PUBLISHED_VERIFY.read_text(encoding="utf-8")
    marker = "      - name: Validate immutable verifier inputs\n        run: |\n"
    assert marker in text
    script_with_tail = text.split(marker, maxsplit=1)[1]
    script, separator, _tail = script_with_tail.partition("\n\n      - uses:")
    assert separator
    return textwrap.dedent(script)


def _working_bash() -> str | None:
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


def test_release_assets_are_immutable_and_bound_to_the_tag_commit() -> None:
    for workflow in (RELEASE, CI):
        text = workflow.read_text(encoding="utf-8")
        assert "--clobber" not in text
        if workflow == RELEASE:
            assert "release_tag_signature_or_target_invalid" in text
            assert "release_tag_drift" in text
            assert "git/ref/tags/$TAG" in text
        assert "release_asset_immutable" in text
        assert "cmp -s" in text


def test_missing_or_lightweight_release_tag_fails_before_draft_creation() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    prepare = _job_block(RELEASE, "prepare-draft")
    assert 'git/ref/tags/$TAG' in text
    assert '--jq .sha 2>/dev/null || true' not in text
    assert "signed_annotated_release_tag_required" in text
    assert '.object.type == "tag"' in text
    assert 'repos/$GITHUB_REPOSITORY/git/tags/$TAG_OBJECT_SHA' in text
    assert "--verify-tag" in text
    assert '--target "$GITHUB_SHA"' in prepare


def test_release_workflow_uses_the_exact_pinned_maintainer_key() -> None:
    prepare = _job_block(RELEASE, "prepare-draft")
    root = json.loads(MAINTAINER_ROOT.read_text(encoding="utf-8"))
    public_key_bytes = MAINTAINER_KEY.read_bytes()
    public_key = public_key_bytes.decode("utf-8").strip()
    key_type, key_body, _comment = public_key.split(" ", maxsplit=2)

    assert root["github_login"] == "EvoRiseKsa"
    assert root["public_key_path"] == (
        "security/release-maintainer-roots/v4.7.0.pub"
    )
    assert root["signature_namespace"] == "git"
    assert root["public_key_sha256"] == hashlib.sha256(
        public_key_bytes
    ).hexdigest()
    assert (
        f'EvoRiseKsa namespaces="git" {key_type} {key_body}' in prepare
    )


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
    publish = _job_block(RELEASE, "publish-release")

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
    assert "environment: evoguard-release-draft" in prepare
    assert "contents: write" in prepare
    assert "EVOGUARD_IMMUTABLE_RELEASES_READ_TOKEN" in prepare
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
    assert "needs: [validate-test, prepare-draft]" in publish
    assert "environment: evoguard-release-publication" in publish
    assert "contents: write" in publish
    assert "EVOGUARD_IMMUTABLE_RELEASES_READ_TOKEN" in publish
    assert "needs.prepare-draft.outputs.pyz-sha256" in publish
    assert "needs.prepare-draft.outputs.sbom-sha256" in publish
    assert "needs.prepare-draft.outputs.sums-sha256" in publish
    assert "actions/download-artifact@" not in publish
    assert "actions/checkout@" not in publish
    assert "actions/setup-python@" not in publish
    assert "pip install" not in publish
    assert "pytest" not in publish
    assert "ruff " not in publish
    assert "mypy " not in publish
    assert "ops/build_pyz.py" not in publish
    assert "ops/generate_spdx_sbom.py" not in publish
    assert "python dist/evo-guard.pyz" not in publish
    assert "python -I dist/evo-guard.pyz" not in publish
    assert "release_asset_readback_mismatch" in publish
    assert 'find "$destination" -mindepth 1 -maxdepth 1' in publish
    assert "-printf '%y\\t%f\\n'" in publish
    assert "steps.prepare-release.outputs.release-body-sha256" in prepare
    assert "needs.prepare-draft.outputs.release-body-sha256" in publish
    for unprivileged in (validate, release_e2e, release_windows, build, attest):
        assert "EVOGUARD_IMMUTABLE_RELEASES_READ_TOKEN" not in unprivileged


def test_future_release_artifact_and_sbom_are_attested_in_a_clean_job() -> None:
    build = _job_block(RELEASE, "build-artifact")
    attest = _job_block(RELEASE, "attest-release-assets")
    attestation_action = "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d"
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


def test_publication_snapshot_validator_rejects_body_and_asset_metadata_tamper(
    tmp_path: Path,
) -> None:
    script = _publication_snapshot_validator_script()
    tag = "v4.7.0"
    target = "a" * 40
    body = "reviewed release notes\n"
    names = ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS")
    expected_assets = {
        name: {"digest": f"sha256:{str(index) * 64}", "size": index * 10}
        for index, name in enumerate(names, start=1)
    }
    uploader = {
        "login": "github-actions[bot]",
        "id": 41898282,
        "type": "Bot",
    }
    draft = {
        "id": 123,
        "tag_name": tag,
        "name": tag,
        "target_commitish": target,
        "prerelease": False,
        "draft": True,
        "immutable": False,
        "published_at": None,
        "body": body,
        "author": {"login": "github-actions[bot]", "id": 41898282},
        "assets": [
            {
                "id": index,
                "name": name,
                "state": "uploaded",
                "size": descriptor["size"],
                "digest": descriptor["digest"],
                "label": "",
                "uploader": uploader,
            }
            for index, (name, descriptor) in enumerate(
                expected_assets.items(), start=1
            )
        ],
    }
    release_path = tmp_path / "release.json"
    expected_path = tmp_path / "expected-assets.json"
    expected_path.write_text(json.dumps(expected_assets), encoding="utf-8")

    def invoke(
        release: dict[str, object],
        *,
        state: str = "draft",
        expected_body: str | None = body,
    ) -> subprocess.CompletedProcess[str]:
        release_path.write_text(json.dumps(release), encoding="utf-8")
        canonical_body = (
            json.dumps(
                expected_body,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        environment = {
            **os.environ,
            "EXPECTED_STATE": state,
            "EXPECTED_RELEASE_BODY_SHA256": hashlib.sha256(
                canonical_body
            ).hexdigest(),
            "RELEASE_ID": "123",
            "TAG": tag,
            "GITHUB_SHA": target,
        }
        return subprocess.run(
            [sys.executable, "-I", "-", str(release_path), str(expected_path)],
            input=script,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
            timeout=10,
        )

    assert invoke(draft).returncode == 0
    null_body = {**draft, "body": None}
    assert invoke(null_body, expected_body=None).returncode == 0
    published = {
        **draft,
        "draft": False,
        "immutable": True,
        "published_at": "2026-09-01T00:00:00Z",
    }
    assert invoke(published, state="published").returncode == 0

    body_tamper = {**draft, "body": body + "changed"}
    assert invoke(body_tamper).returncode != 0
    missing_body = {key: value for key, value in draft.items() if key != "body"}
    assert invoke(missing_body).returncode != 0
    label_tamper = json.loads(json.dumps(draft))
    label_tamper["assets"][0]["label"] = "display label"
    assert invoke(label_tamper).returncode != 0
    null_label_tamper = json.loads(json.dumps(draft))
    null_label_tamper["assets"][0]["label"] = None
    assert invoke(null_label_tamper).returncode != 0
    uploader_tamper = json.loads(json.dumps(draft))
    uploader_tamper["assets"][0]["uploader"]["id"] = 1
    assert invoke(uploader_tamper).returncode != 0
    digest_tamper = json.loads(json.dumps(draft))
    digest_tamper["assets"][0]["digest"] = f"sha256:{'f' * 64}"
    assert invoke(digest_tamper).returncode != 0
    for invalid_id in (None, "1", True, 0):
        id_tamper = json.loads(json.dumps(draft))
        id_tamper["assets"][0]["id"] = invalid_id
        assert invoke(id_tamper).returncode != 0
    duplicate_id = json.loads(json.dumps(draft))
    duplicate_id["assets"][1]["id"] = duplicate_id["assets"][0]["id"]
    assert invoke(duplicate_id).returncode != 0


def test_postpublication_snapshot_validator_rejects_coherent_metadata_tamper(
    tmp_path: Path,
) -> None:
    script = _postpublication_snapshot_validator_script()
    tag = "v4.7.0"
    target = "a" * 40
    body = "reviewed release notes\n"
    expected = {
        "evo-guard.pyz": ("1" * 64, 10),
        "evo-guard.spdx.json": ("2" * 64, 20),
        "SHA256SUMS": ("3" * 64, 30),
    }
    release: object = {
        "id": 123,
        "tag_name": tag,
        "name": tag,
        "target_commitish": target,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "published_at": "2026-09-01T00:00:00Z",
        "body": body,
        "author": {"login": "github-actions[bot]", "id": 41898282},
        "assets": [
            {
                "name": name,
                "state": "uploaded",
                "digest": f"sha256:{descriptor[0]}",
                "size": descriptor[1],
                "label": "",
                "uploader": {
                    "login": "github-actions[bot]",
                    "id": 41898282,
                    "type": "Bot",
                },
            }
            for name, descriptor in expected.items()
        ],
    }
    release_path = tmp_path / "release.json"
    canonical_body = (
        json.dumps(
            body,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    environment = {
        **os.environ,
        "RELEASE_ID": "123",
        "TAG": tag,
        "TARGET_SHA": target,
        "EXPECTED_RELEASE_BODY_SHA256": hashlib.sha256(
            canonical_body
        ).hexdigest(),
        "EXPECTED_PYZ_SHA256": expected["evo-guard.pyz"][0],
        "EXPECTED_PYZ_SIZE": str(expected["evo-guard.pyz"][1]),
        "EXPECTED_SBOM_SHA256": expected["evo-guard.spdx.json"][0],
        "EXPECTED_SBOM_SIZE": str(expected["evo-guard.spdx.json"][1]),
        "EXPECTED_SUMS_SHA256": expected["SHA256SUMS"][0],
        "EXPECTED_SUMS_SIZE": str(expected["SHA256SUMS"][1]),
    }

    def invoke(document: object) -> subprocess.CompletedProcess[str]:
        release_path.write_text(json.dumps(document), encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-I", "-", str(release_path)],
            input=script,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
            timeout=10,
        )

    assert invoke(release).returncode == 0
    assert invoke([]).returncode != 0
    for mutate in (
        lambda value: value.update({"id": 124}),
        lambda value: value.update({"body": body + "changed"}),
        lambda value: value["assets"][0].update({"label": "display"}),
        lambda value: value["assets"][0]["uploader"].update({"id": 1}),
        lambda value: value["assets"][0].update({"digest": "sha256:" + "f" * 64}),
    ):
        tampered = json.loads(json.dumps(release))
        mutate(tampered)
        assert invoke(tampered).returncode != 0


def test_postpublication_manual_dispatch_fails_closed_off_default_branch() -> None:
    bash = _working_bash()
    if bash is None:
        pytest.skip("Bash is unavailable")
    script = _postpublication_input_validator_script()
    environment = {
        **os.environ,
        "DEFAULT_BRANCH": "main",
        "TAG": "v4.7.0",
        "TARGET_SHA": "a" * 40,
        "RELEASE_ID": "123",
        "TAG_OBJECT_SHA": "b" * 40,
        "EXPECTED_RELEASE_BODY_SHA256": "c" * 64,
        "EXPECTED_PYZ_SHA256": "d" * 64,
        "EXPECTED_PYZ_SIZE": "10",
        "EXPECTED_SBOM_SHA256": "e" * 64,
        "EXPECTED_SBOM_SIZE": "20",
        "EXPECTED_SUMS_SHA256": "f" * 64,
        "EXPECTED_SUMS_SIZE": "30",
    }

    def invoke(ref: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [bash],
            input=script,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
            env={**environment, "GITHUB_REF": ref},
        )

    assert invoke("refs/heads/main").returncode == 0
    wrong = invoke("refs/heads/unprotected-verifier")
    assert wrong.returncode != 0
    assert "postpublication_verifier_requires_default_branch" in wrong.stdout


def test_future_release_asset_contract_is_exact_and_filename_ordered() -> None:
    build = _job_block(RELEASE, "build-artifact")
    prepare = _job_block(RELEASE, "prepare-draft")
    protected_publish = _job_block(RELEASE, "publish-release")
    tag_verify = _job_block(CI, "publish-pyz")
    assert "python -I ops/generate_spdx_sbom.py" in build
    assert "python -I ops/generate_spdx_sbom.py" in tag_verify
    assert "--version \"${TAG#v}\"" in build
    assert "--version \"${GITHUB_REF_NAME#v}\"" in tag_verify
    for block in (build, prepare, protected_publish, tag_verify):
        assert "evo-guard.pyz" in block
        assert "evo-guard.spdx.json" in block
        assert "SHA256SUMS" in block
    for block in (build, tag_verify):
        checksum = "sha256sum evo-guard.pyz evo-guard.spdx.json > SHA256SUMS"
        assert checksum in block
    for block in (prepare, tag_verify):
        assert "find dist -mindepth 1 -maxdepth 1" in block
        assert "-printf '%y\\t%f\\n'" in block
        assert "release_checksum_format_invalid" in block
    assert 'find "$destination" -mindepth 1 -maxdepth 1' in protected_publish
    assert "release_asset_readback_mismatch" in protected_publish


def test_release_is_manual_and_accepts_only_the_default_branch() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "\n  push:" not in text
    assert "release/v" not in text
    assert "permissions: {}" in text
    default_branch_guard = (
        "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
    )
    dispatch_guard = _job_block(RELEASE, "dispatch-ref-guard")
    assert "if: always()" in dispatch_guard
    assert "permissions: {}" in dispatch_guard
    assert 'test "$GITHUB_REF" = "refs/heads/$DEFAULT_BRANCH"' in dispatch_guard
    assert "release_dispatch_requires_default_branch" in dispatch_guard
    assert "timeout-minutes:" in dispatch_guard
    for job in (
        "validate-test",
        "release-e2e",
        "release-windows-e2e",
        "build-artifact",
        "attest-release-assets",
        "prepare-draft",
        "publish-release",
    ):
        block = _job_block(RELEASE, job)
        assert default_branch_guard in block
        assert "timeout-minutes:" in block


def test_control_plane_token_documentation_covers_every_read_endpoint() -> None:
    documentation = (ROOT / "docs" / "RELEASING.md").read_text(encoding="utf-8")
    for permission in (
        "Metadata read",
        "Administration read",
        "Actions read",
        "Checks read",
        "Contents read",
    ):
        assert permission in documentation


def test_draft_write_requires_immediate_live_state_evidence() -> None:
    prepare = _job_block(RELEASE, "prepare-draft")
    mutation_at = prepare.index('gh release create "$TAG"')

    assert "environment: evoguard-release-draft" in prepare
    assert "repos/$GITHUB_REPOSITORY/immutable-releases" in prepare
    assert ".enabled == true" in prepare
    assert ".enforced_by_owner | type == \"boolean\"" in prepare
    assert "immutable_releases_required" in prepare
    assert "repos/$GITHUB_REPOSITORY/git/ref/heads/main" in prepare
    assert "repos/$GITHUB_REPOSITORY/compare/$GITHUB_SHA...$MAIN_HEAD_SHA" in prepare
    assert ".merge_base_commit.sha == $source" in prepare
    assert "release_source_not_in_protected_main_history" in prepare
    assert "repos/$GITHUB_REPOSITORY/branches/main" in prepare
    assert ".protected == true" in prepare
    assert "release_source_not_protected_main" in prepare
    assert "repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA" in prepare
    assert ".commit.verification.verified == true" in prepare
    assert '.commit.verification.reason == "valid"' in prepare
    assert "release_source_signature_invalid" in prepare
    assert "release_tag_not_signed_by_maintainer_root" in prepare
    assert "ssh-keygen -Y verify -q" in prepare
    assert prepare.count("ssh-keygen -Y verify -q") == 1
    assert 'namespaces="git" ssh-ed25519' in prepare
    assert "AAAAC3NzaC1lZDI1NTE5AAAAIDZCepQbTxouwR5UwSKMF+4RvlK/MRQ+D9HE+fxJOKdi" in prepare
    assert "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG" in prepare
    assert "repos/$GITHUB_REPOSITORY/git/tags/$TAG_OBJECT_SHA" in prepare
    assert ".object.sha == $sha" in prepare
    assert "check-runs?filter=latest&per_page=100" in prepare
    assert prepare.count("release_check_run_pagination_incomplete") == 2
    assert prepare.count(".total_count == (.check_runs | length)") == 2
    assert prepare.count(".total_count <= 100") == 2
    assert "max_by(.id)" in prepare
    assert '($latest.conclusion // "")' in prepare
    assert '"missing"' in prepare
    assert "release_required_checks_drift" in prepare
    assert "57789" in prepare
    assert "15368" in prepare
    assert prepare.count("repos/$GITHUB_REPOSITORY/immutable-releases") == 2
    assert prepare.count("repos/$GITHUB_REPOSITORY/git/ref/heads/main") >= 2
    assert prepare.count("repos/$GITHUB_REPOSITORY/branches/main") == 2
    assert prepare.count("check-runs?filter=latest&per_page=100") >= 2
    assert "all($expected | to_entries[]" in prepare
    assert "verify_mutable_authority()" in prepare
    assert 'checks_json="$(control_api' in prepare

    for evidence in (
        "repos/$GITHUB_REPOSITORY/immutable-releases",
        "repos/$GITHUB_REPOSITORY/git/ref/heads/main",
        "repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA",
        "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG",
        "repos/$GITHUB_REPOSITORY/git/tags/$TAG_OBJECT_SHA",
        "check-runs?filter=latest&per_page=100",
    ):
        assert prepare.index(evidence) < mutation_at

    transferred_assets = prepare.index("Verify the transferred asset set")
    state_rechecks = [
        match.start()
        for match in re.finditer(
            r"^\s+verify_mutable_authority$", prepare, flags=re.MULTILINE
        )
    ]
    assert len(state_rechecks) == 2
    assert transferred_assets < state_rechecks[0] < mutation_at
    assert prepare.index('upload_release_asset "$asset"') < state_rechecks[1]


def test_release_source_ancestry_accepts_identical_or_advanced_main_only() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    filters = re.findall(
        r'jq -e --arg source "\$GITHUB_SHA" \'(?P<filter>.*?)\'\s+<<<',
        text,
        flags=re.DOTALL,
    )
    assert len(filters) == 3
    assert len({re.sub(r"\s+", " ", item).strip() for item in filters}) == 1
    assert "head_commit" not in filters[0]
    assert "merge_base_commit.sha == $source" in filters[0]
    assert '.status == "identical" and .ahead_by == 0' in filters[0]
    assert '.status == "ahead" and .ahead_by > 0' in filters[0]

    jq = shutil.which("jq")
    if jq is None:
        pytest.skip("jq executable is unavailable on this platform")
    source = "a" * 40
    fixtures = [
        ({
            "base_commit": {"sha": source},
            "merge_base_commit": {"sha": source},
            "status": "identical",
            "ahead_by": 0,
            "behind_by": 0,
            "head_commit": None,
        }, True),
        ({
            "base_commit": {"sha": source},
            "merge_base_commit": {"sha": source},
            "status": "ahead",
            "ahead_by": 2,
            "behind_by": 0,
            "head_commit": None,
        }, True),
        ({
            "base_commit": {"sha": source},
            "merge_base_commit": {"sha": "b" * 40},
            "status": "diverged",
            "ahead_by": 1,
            "behind_by": 1,
            "head_commit": None,
        }, False),
    ]
    for document, accepted in fixtures:
        result = subprocess.run(
            [jq, "-e", "--arg", "source", source, filters[0]],
            input=json.dumps(document),
            text=True,
            capture_output=True,
            check=False,
        )
        assert (result.returncode == 0) is accepted


def test_protected_publish_requires_exact_rulesets_and_retired_tag_transport() -> None:
    publish = _job_block(RELEASE, "publish-release")
    patch_at = publish.index("--method PATCH")

    for variable in (
        "EVOGUARD_RELEASE_MAIN_RULESET_ID",
        "EVOGUARD_RELEASE_TAG_RULESET_ID",
    ):
        assert variable in publish
    assert "rulesets?includes_parents=true&targets=branch&per_page=100" in publish
    assert "rulesets/$EXPECTED_MAIN_RULESET_ID?includes_parents=true" in publish
    assert 'has("bypass_actors")' in publish
    assert '.bypass_actors == null' in publish
    assert 'refs/heads/main' in publish
    assert '"pull_request"' in publish
    assert '"required_status_checks"' in publish
    assert "strict_required_status_checks_policy == true" in publish
    assert "release_main_ruleset_inventory_not_exact" in publish
    assert "release_main_ruleset_bypass_or_scope_drift" in publish
    assert "rulesets?includes_parents=true&targets=tag&per_page=100" in publish
    assert "rulesets/$EXPECTED_TAG_RULESET_ID?includes_parents=true" in publish
    assert 'refs/tags/v*' in publish
    assert '"creation", "deletion", "non_fast_forward", "update"' in publish
    assert '.current_user_can_bypass == "never"' in publish
    assert '"actor_type": "DeployKey"' in publish
    assert '"bypass_mode": "always"' in publish
    assert "release_tag_ruleset_inventory_not_exact" in publish
    assert "release_tag_ruleset_contract_not_exact" in publish
    assert "repos/$GITHUB_REPOSITORY/keys?per_page=100" in publish
    assert "([.[][]] | length) == 0" in publish
    assert "release_tag_transport_not_retired" in publish
    assert "EVOGUARD_RELEASE_TAG_DEPLOY_KEY_ID" not in publish
    assert "EVOGUARD_RELEASE_TAG_DEPLOY_KEY_FINGERPRINT" not in publish
    assert "secrets.EVOGUARD_RELEASE_TAG_DEPLOY_KEY" not in publish
    assert "verify_live_authority()" in publish
    assert publish.count("verify_live_authority") == 4
    assert publish.index("rulesets/$EXPECTED_TAG_RULESET_ID") < patch_at


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


def test_release_workflow_prepares_a_draft_then_publishes_under_live_proof() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    publish = _job_block(RELEASE, "publish-release")
    create = re.search(
        r'gh release create "\$TAG"(?P<args>.*?)(?:\n\s*fi\n)',
        text,
        flags=re.DOTALL,
    )
    assert create is not None
    assert "--draft" in create.group("args")
    assert "--verify-tag" in create.group("args")
    assert '--target "$GITHUB_SHA"' in create.group("args")
    assert text.index("immutable_releases_required") < create.start()
    assert text.index("release_source_signature_invalid") < create.start()
    assert text.index("release_tag_not_signed_by_maintainer_root") < create.start()
    assert text.index("release_required_checks_drift") < create.start()
    assert "repos/$GITHUB_REPOSITORY/releases?per_page=100" in text
    assert "release_tag_match_not_unique" in text
    assert "release_tag_drift" in text
    assert "gh release edit" not in text
    assert "--draft=false" not in text
    assert "--draft false" not in text
    assert "environment: evoguard-release-publication" in publish
    assert "release_publish_environment_not_exact" in publish
    assert ".can_admins_bypass == false" in publish
    assert ".deployment_branch_policy.protected_branches == false" in publish
    assert ".deployment_branch_policy.custom_branch_policies == true" in publish
    assert '(.protection_rules | length) == 2' in publish
    assert 'select(.type == "branch_policy")' in publish
    assert 'select(.type == "required_reviewers")' in publish
    assert "$review_rules[0].prevent_self_review == true" in publish
    assert "($review_rules[0].reviewers | length) == 1" in publish
    assert '$review_rules[0].reviewers[0].type == "User"' in publish
    assert "$review_rules[0].reviewers[0].reviewer.id == 304223352" in publish
    assert (
        '$review_rules[0].reviewers[0].reviewer.login == "MANA-awam"' in publish
    )
    assert (
        "environments/evoguard-release-publication/"
        "deployment-branch-policies?per_page=100" in publish
    )
    assert ".[0].total_count == 1" in publish
    assert ".[0].branch_policies[0].name == \"main\"" in publish
    assert ".[0].branch_policies[0].type == \"branch\"" in publish
    assert "release_publish_branch_policy_not_exact_main" in publish
    assert "verify_live_authority()" in publish
    assert "validate_release_snapshot()" in publish
    assert "readback_exact_assets()" in publish
    assert 'release_api "repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID"' in publish
    assert '"repos/$GITHUB_REPOSITORY/releases/assets/$asset_id"' in publish
    assert "release_api -H 'Accept: application/octet-stream'" not in publish
    assert "gh api -H 'Accept: application/octet-stream'" in publish
    assert 'gh release download "$TAG"' not in publish
    assert publish.count("verify_unique_tag_release") == 4
    assert "release_tag_match_not_unique_or_id_drift" in publish
    published_join = publish.index(
        "# The by-tag REST endpoint exposes published releases only."
    )
    published_condition = publish.index(
        "if jq -e '.draft == false and .immutable == true'", published_join
    )
    by_tag_lookup = publish.index(
        '"repos/$GITHUB_REPOSITORY/releases/tags/$TAG"', published_condition
    )
    assert published_join < published_condition < by_tag_lookup
    patch_at = publish.index("--method PATCH")
    draft_bytes_at = publish.index(
        'readback_exact_assets "$BEFORE"'
    )
    immediate_at = publish.index(
        'IMMEDIATE="$RUNNER_TEMP/release-immediately-before-publication.json"'
    )
    marker_at = publish.index("publication-patch-started")
    assert draft_bytes_at < immediate_at < marker_at < patch_at
    assert publish.rfind("verify_live_authority", draft_bytes_at, patch_at) >= 0
    assert (
        publish.index('validate_release_snapshot "$IMMEDIATE" draft') < patch_at
    )
    post_state_at = publish.index(
        'validate_release_snapshot "$AFTER" published', patch_at
    )
    post_authority_at = publish.index("verify_live_authority", post_state_at)
    final_state_at = publish.index(
        'validate_release_snapshot "$FINAL" published', post_authority_at
    )
    post_bytes_at = publish.index(
        'readback_exact_assets "$FINAL"', final_state_at
    )
    assert patch_at < post_state_at < post_authority_at < final_state_at < post_bytes_at
    assert '.draft == false and .immutable == true' in publish
    assert "release_asset_readback_mismatch" in publish
    assert "release body digest changed" in publish
    assert 'or "label" not in asset' in publish
    assert 'asset["label"] != ""' in publish
    assert 'uploader.get("login") != "github-actions[bot]"' in publish
    assert 'uploader.get("id") != 41898282' in publish
    assert "--method DELETE" not in publish
    assert "ruff check" in text
    assert "ops/build_pyz.py ops/generate_spdx_sbom.py" in text
    assert "mypy evoom_guard/" in text
    assert "mypy --strict" in text
    assert "python -m pytest tests/ -q" in text
    assert 'default: "v2.0.0"' not in text


@pytest.mark.parametrize(
    ("mode", "accepted", "created"),
    (
        ("existing", True, False),
        ("create", True, True),
        ("duplicate", False, False),
        ("not-visible-after-create", False, True),
    ),
)
def test_draft_create_or_select_path_is_unique_and_polls_by_numeric_id(
    tmp_path: Path,
    mode: str,
    accepted: bool,
    created: bool,
) -> None:
    bash = _working_bash()
    jq = shutil.which("jq")
    if bash is None or jq is None:
        pytest.skip("Bash and jq are required for the draft selection harness")
    script = textwrap.dedent(
        f"""
        set -euo pipefail
        verify_mutable_authority() {{ :; }}
        capture_tag_matches() {{
          local output="$1"
          case "$MOCK_MODE" in
            existing) printf '%s\n' "$MOCK_ONE" > "$output" ;;
            create)
              if [ "$(cat "$STATE_FILE")" = 0 ]; then
                printf '%s\n' '[]' > "$output"
              else
                printf '%s\n' "$MOCK_ONE" > "$output"
              fi
              ;;
            duplicate) printf '%s\n' "$MOCK_DUPLICATE" > "$output" ;;
            not-visible-after-create) printf '%s\n' '[]' > "$output" ;;
            *) return 31 ;;
          esac
        }}
        gh() {{
          printf '%s\n' "$*" >> "$CALL_LOG"
          if [[ "$*" == release\\ create* ]]; then
            printf '1\n' > "$STATE_FILE"
            return 0
          fi
          return 32
        }}
        sleep() {{ :; }}
        {_prepare_draft_create_or_select_script()}
        printf '%s\n' "$RELEASE_ID" > "$SELECTED_ID"
        """
    )
    state = tmp_path / "state"
    state.write_text("0\n", encoding="utf-8", newline="\n")
    calls = tmp_path / "gh-calls.log"
    selected = tmp_path / "selected-id"
    one = [{"id": 123, "tag_name": "v4.7.1"}]
    duplicate = [*one, {"id": 124, "tag_name": "v4.7.1"}]
    result = subprocess.run(
        [bash],
        input=script,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
        env={
            **os.environ,
            "MOCK_MODE": mode,
            "MOCK_ONE": json.dumps(one),
            "MOCK_DUPLICATE": json.dumps(duplicate),
            "STATE_FILE": state.as_posix(),
            "CALL_LOG": calls.as_posix(),
            "SELECTED_ID": selected.as_posix(),
            "RUNNER_TEMP": tmp_path.as_posix(),
            "GITHUB_REPOSITORY": "EvoRiseKsa/EvoOM-Guard-m",
            "GITHUB_SHA": "a" * 40,
            "TAG": "v4.7.1",
        },
    )
    assert (result.returncode == 0) is accepted, result.stdout + result.stderr
    call_text = calls.read_text(encoding="utf-8") if calls.exists() else ""
    assert ("release create" in call_text) is created
    if accepted:
        assert selected.read_text(encoding="utf-8").strip() == "123"
    if created:
        assert "--draft" in call_text
        assert "--verify-tag" in call_text
        assert "--target" in call_text
        assert "a" * 40 in call_text


@pytest.mark.parametrize(
    ("records", "release_id", "accepted"),
    (
        ([], "123", False),
        ([{"id": 123, "tag_name": "v4.7.1"}], "123", True),
        (
            [
                {"id": 123, "tag_name": "v4.7.1"},
                {"id": 124, "tag_name": "v4.7.1"},
            ],
            "123",
            False,
        ),
        ([{"id": 124, "tag_name": "v4.7.1"}], "123", False),
    ),
)
def test_draft_inventory_requires_one_exact_numeric_release_id(
    tmp_path: Path,
    records: list[dict[str, object]],
    release_id: str,
    accepted: bool,
) -> None:
    bash = _working_bash()
    jq = shutil.which("jq")
    if bash is None or jq is None:
        pytest.skip("Bash and jq are required for the numeric draft harness")
    functions = _prepare_draft_numeric_api_functions()
    script = textwrap.dedent(
        f"""
        set -euo pipefail
        gh() {{
          printf '%s\n' "$*" >> "$CALL_LOG"
          if [[ "$*" == *"/releases?per_page=100"* ]]; then
            printf '%s\n' "$MOCK_RELEASE_PAGES"
            return 0
          fi
          return 22
        }}
        {functions}
        if verify_unique_tag_release; then
          test "$EXPECT_ACCEPTED" = true
        else
          test "$EXPECT_ACCEPTED" = false
        fi
        """
    )
    result = subprocess.run(
        [bash],
        input=script,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
        env={
            **os.environ,
            "CALL_LOG": (tmp_path / "gh-calls.log").as_posix(),
            "RUNNER_TEMP": tmp_path.as_posix(),
            "GITHUB_REPOSITORY": "EvoRiseKsa/EvoOM-Guard-m",
            "GITHUB_SHA": "a" * 40,
            "TAG": "v4.7.1",
            "RELEASE_ID": release_id,
            "EXPECT_ACCEPTED": str(accepted).lower(),
            "MOCK_RELEASE_PAGES": json.dumps([records]),
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_draft_by_tag_404_does_not_block_numeric_record_and_asset_readback(
    tmp_path: Path,
) -> None:
    bash = _working_bash()
    jq = shutil.which("jq")
    if bash is None or jq is None:
        pytest.skip("Bash and jq are required for the numeric draft harness")
    target = "a" * 40
    release = {
        "id": 123,
        "tag_name": "v4.7.1",
        "name": "v4.7.1",
        "target_commitish": target,
        "prerelease": False,
        "draft": True,
        "immutable": False,
        "published_at": None,
        "author": {"login": "github-actions[bot]", "id": 41898282},
        "assets": [
            {
                "id": 456,
                "name": "SHA256SUMS",
                "state": "uploaded",
            }
        ],
    }
    functions = _prepare_draft_numeric_api_functions()
    script = textwrap.dedent(
        f"""
        set -euo pipefail
        gh() {{
          printf '%s\n' "$*" >> "$CALL_LOG"
          if [[ "$*" == *"/releases/tags/"* ]]; then
            return 22
          elif [[ "$*" == *"/releases?per_page=100"* ]]; then
            printf '%s\n' "$MOCK_RELEASE_PAGES"
          elif [[ "$*" == *"/releases/123"* ]]; then
            printf '%s\n' "$MOCK_RELEASE_RECORD"
          elif [[ "$*" == *"/releases/assets/456"* ]]; then
            printf '%s' "$MOCK_ASSET_BYTES"
          else
            return 23
          fi
        }}
        {functions}
        matches="$RUNNER_TEMP/matches.json"
        record="$RUNNER_TEMP/release.json"
        output="$RUNNER_TEMP/SHA256SUMS"
        capture_tag_matches "$matches"
        verify_unique_tag_release
        capture_release_record "$record"
        download_release_asset 456 "$output"
        test "$(cat "$output")" = "$MOCK_ASSET_BYTES"
        """
    )
    calls = tmp_path / "gh-calls.log"
    result = subprocess.run(
        [bash],
        input=script,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
        env={
            **os.environ,
            "CALL_LOG": calls.as_posix(),
            "RUNNER_TEMP": tmp_path.as_posix(),
            "GITHUB_REPOSITORY": "EvoRiseKsa/EvoOM-Guard-m",
            "GITHUB_SHA": target,
            "TAG": "v4.7.1",
            "RELEASE_ID": "123",
            "MOCK_RELEASE_PAGES": json.dumps([[release]]),
            "MOCK_RELEASE_RECORD": json.dumps(release),
            "MOCK_ASSET_BYTES": "numeric-id-readback",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    call_text = calls.read_text(encoding="utf-8")
    assert "/releases/123" in call_text
    assert "/releases/assets/456" in call_text
    assert "/releases/tags/" not in call_text


@pytest.mark.parametrize(
    "mutation",
    ("valid", "http", "id", "name", "size", "digest", "label", "uploader"),
)
def test_numeric_asset_upload_binds_raw_body_url_and_provider_response(
    tmp_path: Path,
    mutation: str,
) -> None:
    bash = _working_bash()
    jq = shutil.which("jq")
    if bash is None or jq is None:
        pytest.skip("Bash and jq are required for the numeric upload harness")
    dist = tmp_path / "dist"
    dist.mkdir()
    body = b"exact release asset bytes\n"
    asset = dist / "evo-guard.pyz"
    asset.write_bytes(body)
    digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
    response: dict[str, object] = {
        "id": 456,
        "name": asset.name,
        "state": "uploaded",
        "size": len(body),
        "digest": digest,
        "label": "",
        "uploader": {
            "login": "github-actions[bot]",
            "id": 41898282,
            "type": "Bot",
        },
    }
    if mutation == "id":
        response["id"] = 0
    elif mutation == "name":
        response["name"] = "other.pyz"
    elif mutation == "size":
        response["size"] = len(body) + 1
    elif mutation == "digest":
        response["digest"] = f"sha256:{'f' * 64}"
    elif mutation == "label":
        response["label"] = "display"
    elif mutation == "uploader":
        response["uploader"] = {
            "login": "attacker",
            "id": 1,
            "type": "User",
        }
    script = textwrap.dedent(
        f"""
        set -euo pipefail
        curl() {{
          printf '%s\n' "$*" >> "$CALL_LOG"
          local output=''
          while [ "$#" -gt 0 ]; do
            if [ "$1" = --output ]; then
              output="$2"
              shift 2
            else
              shift
            fi
          done
          printf '%s' "$MOCK_UPLOAD_RESPONSE" > "$output"
          printf '%s' "$MOCK_HTTP_STATUS"
        }}
        {_prepare_draft_upload_function()}
        if upload_release_asset evo-guard.pyz; then
          test "$EXPECT_ACCEPTED" = true
        else
          test "$EXPECT_ACCEPTED" = false
        fi
        """
    )
    calls = tmp_path / "curl-calls.log"
    result = subprocess.run(
        [bash],
        input=script,
        text=True,
        capture_output=True,
        check=False,
        cwd=tmp_path,
        timeout=15,
        env={
            **os.environ,
            "CALL_LOG": calls.as_posix(),
            "RUNNER_TEMP": tmp_path.as_posix(),
            "GITHUB_REPOSITORY": "EvoRiseKsa/EvoOM-Guard-m",
            "RELEASE_ID": "123",
            "GH_TOKEN": "test-token-not-a-secret",
            "MOCK_UPLOAD_RESPONSE": json.dumps(response),
            "MOCK_HTTP_STATUS": "500" if mutation == "http" else "201",
            "EXPECT_ACCEPTED": str(mutation == "valid").lower(),
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    call_text = calls.read_text(encoding="utf-8")
    assert "/releases/123/assets?name=evo-guard.pyz&label=" in call_text
    assert "--data-binary @dist/evo-guard.pyz" in call_text
    assert "Content-Type: application/octet-stream" in call_text
    assert "/releases/tags/" not in call_text


def test_release_rerun_only_uploads_missing_assets_to_a_draft() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    prepare = _job_block(RELEASE, "prepare-draft")
    assert 'if [ "$RELEASE_IS_DRAFT" != "true" ]' in text
    assert "published release is missing $asset" in text
    assert 'upload_release_asset "$asset"' in text
    assert "https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/" in text
    assert 'cmp -s "dist/$asset" "existing-release-assets/$asset"' in text
    assert "unexpected existing assets" in text
    assert "final release asset set is not exact" in text
    assert "release_asset_readback_mismatch" in text
    assert "final-release-assets" in text
    assert "SHA256SUMS evo-guard.pyz evo-guard.spdx.json" in text
    assert "for asset in evo-guard.pyz evo-guard.spdx.json SHA256SUMS" in text
    assert "capture_tag_matches" in prepare
    assert "--paginate --slurp" in prepare
    assert prepare.count("verify_unique_tag_release") == 2
    assert 'RELEASE_ID="$(jq -r \'.[0].id\' "$RELEASE_MATCHES")"' in prepare
    assert '"repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID"' in prepare
    assert '--argjson id "$RELEASE_ID"' in prepare
    assert ".id == $id" in prepare
    assert '"repos/$GITHUB_REPOSITORY/releases/tags/$TAG"' not in prepare
    assert '"repos/$GITHUB_REPOSITORY/releases/assets/$asset_id"' in prepare
    assert "created_draft_not_uniquely_visible" in prepare
    create_at = prepare.index('gh release create "$TAG"')
    draft_readback_at = prepare.index(
        'capture_release_record "$RELEASE_RECORD_FILE"', create_at
    )
    assert create_at < draft_readback_at


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
    assert "prepublication_signed_tag_verified" in publish_job
    assert "prepublication_draft_verified" in publish_job
    assert '[ "$GITHUB_EVENT_NAME" = "push" ]' in publish_job
    assert "gh api graphql" in publish_job
    assert ".data.repository.release == null" in publish_job
    assert "release_lookup_invalid" in publish_job
    assert "release_lookup_failed" in publish_job
    missing_at = publish_job.index("prepublication_signed_tag_verified")
    query_at = publish_job.index("gh api graphql")
    view_at = publish_job.index('gh release view "$GITHUB_REF_NAME"')
    assert query_at < missing_at < view_at


def test_postpublication_verifier_is_mandatory_read_only_and_reproducible() -> None:
    release = RELEASE.read_text(encoding="utf-8")
    verifier = PUBLISHED_VERIFY.read_text(encoding="utf-8")
    post = _job_block(RELEASE, "post-publication-verify")

    assert "needs: [validate-test, prepare-draft, publish-release]" in post
    assert "permissions:\n      contents: read" in post
    assert "uses: ./.github/workflows/release-published-verify.yml" in post
    for field in (
        "tag",
        "target_sha",
        "release_id",
        "tag_object_sha",
        "release_body_sha256",
        "pyz_sha256",
        "pyz_size",
        "sbom_sha256",
        "sbom_size",
        "sums_sha256",
        "sums_size",
    ):
        assert f"      {field}:" in post
    assert release.index("--method PATCH") < release.index(
        "  post-publication-verify:"
    )

    assert "workflow_call:" in verifier
    assert "workflow_dispatch:" in verifier
    verifier_job = _job_block(PUBLISHED_VERIFY, "verify-published-release")
    assert "\n    if:" not in verifier_job.split("    steps:\n", maxsplit=1)[0]
    assert 'test "$GITHUB_REF" = "refs/heads/$DEFAULT_BRANCH"' in verifier
    assert "postpublication_verifier_requires_default_branch" in verifier
    assert "permissions:\n  contents: read" in verifier
    assert "contents: write" not in verifier
    assert "actions/upload-artifact@" not in verifier
    assert "actions/download-artifact@" not in verifier
    assert "persist-credentials: false" in verifier
    assert "python -I ops/build_pyz.py" in verifier
    assert "python -I ops/generate_spdx_sbom.py" in verifier
    job_prefix = verifier_job.split("    steps:\n", maxsplit=1)[0]
    rebuild = verifier[
        verifier.index("      - name: Rebuild the exact deterministic asset set") :
        verifier.index("      - name: Verify exact immutable provider state")
    ]
    assert "GH_TOKEN" not in job_prefix
    assert "GH_TOKEN" not in rebuild
    assert "GH_TOKEN: ${{ github.token }}" in verifier
    assert "EXPECTED_RELEASE_BODY_SHA256" in verifier
    assert "published release body digest changed" in verifier
    assert "repos/$GITHUB_REPOSITORY/releases/tags/$TAG" in verifier
    assert 'namespaces="git" ssh-ed25519' in verifier
    assert "ssh-keygen -Y verify -q" in verifier
    assert (
        "AAAAC3NzaC1lZDI1NTE5AAAAIDZCepQbTxouwR5UwSKMF+4RvlK/"
        "MRQ+D9HE+fxJOKdi" in verifier
    )
    assert 'release.get("immutable") is not True' in verifier
    assert 'asset.get("label") != ""' in verifier
    assert "gh release download" in verifier
    assert 'cmp -s "dist/$asset"' in verifier


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
