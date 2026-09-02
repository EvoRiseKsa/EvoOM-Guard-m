# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Single-source project-status schema, semantics, and rendering gates."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from jsonschema import Draft202012Validator

from ops import render_project_status
from tools.ci import validate_release_candidate_scope as candidate_scope

ROOT = Path(__file__).parents[1]


def _project_status_v2_fixture() -> dict[str, object]:
    configured_status = json.loads(
        (ROOT / "PROJECT_STATUS.json").read_text(encoding="utf-8")
    )
    configured = configured_status["release_exceptions"]["published_unledgered"]
    first = configured[0] if isinstance(configured, list) else configured
    second = {
        "record": (
            "evidence/release-operations/v4.4.1/UNSEALED_STATUS.json"
        ),
        "record_sha256": "1" * 64,
        "erratum": "docs/errata/V4.4.1-LEDGER.md",
        "key_disposition": (
            "evidence/release-operations/v4.4.1/"
            "LEDGER_KEY_DISPOSITION.json"
        ),
    }
    historical_ledger = (
        configured_status.get("historical_evidence", {}).get(
            "latest_validated_a_h_ledger"
        )
        or configured_status.get("published_release", {}).get("ledger")
        or "evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json"
    )
    return {
        "published_release": {"ledger": historical_ledger},
        "release_exceptions": {"published_unledgered": [first, second]},
        "release_pipeline": configured_status["release_pipeline"],
        "schema_version": "evoguard-project-status-v2",
        "source": {
            "architecture": configured_status["source"]["architecture"],
            "lifecycle": "release-candidate",
            "relation_to_latest_release": "descendant",
        },
    }


def _project_status_v3_fixture() -> dict[str, object]:
    configured_status = json.loads(
        (ROOT / "PROJECT_STATUS.json").read_text(encoding="utf-8")
    )
    record_path = "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json"
    signature_path = f"{record_path}.sig"
    record_bytes = (ROOT / record_path).read_bytes()
    signature_bytes = (ROOT / signature_path).read_bytes()
    historical_ledger = (
        configured_status.get("historical_evidence", {}).get(
            "latest_validated_a_h_ledger"
        )
        or configured_status.get("published_release", {}).get("ledger")
        or "evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json"
    )
    return {
        "published_release": {
            "record": record_path,
            "record_sha256": hashlib.sha256(record_bytes).hexdigest(),
            "signature": signature_path,
            "signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
        },
        "historical_evidence": {
            "latest_validated_a_h_ledger": historical_ledger,
        },
        "release_exceptions": configured_status["release_exceptions"],
        "release_pipeline": {
            "activation_model": "manual-dispatch",
            "contract": "simple-release-v1",
            "evidence_scope": "durable-repository-record",
            "implementation": "implemented",
            "legacy_workflow": "archived-inert",
        },
        "schema_version": "evoguard-project-status-v3",
        "source": {
            "architecture": configured_status["source"]["architecture"],
            "lifecycle": "release-line",
            "relation_to_latest_release": "descendant",
        },
    }


def _as_project_status_v2(
    status: render_project_status.Status,
) -> render_project_status.Status:
    """Detach live v3 authority when a test exercises legacy v1/v2 semantics."""

    return replace(
        status,
        schema_version="evoguard-project-status-v2",
        direct_release_record_path=None,
        direct_release_record_sha256=None,
        direct_release_signature_path=None,
        direct_release_signature_sha256=None,
    )


def _minimal_v2_ledger(version: str = "4.4.0") -> dict[str, object]:
    tag = f"v{version}"
    return {
        "schema_version": "evoguard-release-ledger-v2",
        "project": {"name": "EvoOM Guard", "version": version},
        "release": {
            "repository": "EvoRiseKsa/EvoOM-Guard-m",
            "tag": tag,
            "commit_sha": "1" * 40,
            "state": "published",
            "prerelease": False,
            "immutable": True,
            "release_url": (
                "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/"
                f"{tag}"
            ),
        },
        "artifacts": [
            {"name": "evo-guard.pyz"},
            {"name": "evo-guard.spdx.json"},
            {"name": "SHA256SUMS"},
        ],
        "attestations": {
            "build_provenance": {
                "signer_workflow": (
                    ".github/workflows/evoguard-build-release-artifact.yml"
                ),
                "subject_name": "evo-guard.pyz",
            },
            "spdx_provenance": {"subject_name": "evo-guard.spdx.json"},
            "sbom_provenance": {"subject_name": "evo-guard.pyz"},
            "release": {
                "asset_subjects": [
                    {"name": "evo-guard.pyz"},
                    {"name": "evo-guard.spdx.json"},
                    {"name": "SHA256SUMS"},
                ]
            },
        },
    }


class ProjectStatusTests(unittest.TestCase):
    def test_machine_readable_status_matches_its_public_schema(self) -> None:
        status = json.loads((ROOT / "PROJECT_STATUS.json").read_text(encoding="utf-8"))
        schema_name = {
            "evoguard-project-status-v1": "project-status-v1.schema.json",
            "evoguard-project-status-v2": "project-status-v2.schema.json",
            "evoguard-project-status-v3": "project-status-v3.schema.json",
        }[status["schema_version"]]
        schema = json.loads(
            (ROOT / "tests/status" / schema_name).read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema).iter_errors(status),
            key=lambda error: list(error.absolute_path),
        )
        self.assertEqual(
            errors,
            [],
            "\n".join(
                f"{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
                for error in errors
            ),
        )

    def test_project_status_v2_schema_and_parser_preserve_ordered_history(
        self,
    ) -> None:
        status = _project_status_v2_fixture()
        schema = json.loads(
            (
                ROOT / "tests/status/project-status-v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        self.assertEqual(
            list(Draft202012Validator(schema).iter_errors(status)),
            [],
        )
        parsed = render_project_status.load_status(
            ROOT,
            raw=(json.dumps(status) + "\n").encode(),
        )
        self.assertEqual(parsed.schema_version, "evoguard-project-status-v2")
        self.assertEqual(
            tuple(
                authority.record_path
                for authority in parsed.published_unledgered_authorities
            ),
            (
                "evidence/release-operations/v4.4.0/UNSEALED_STATUS.json",
                "evidence/release-operations/v4.4.1/UNSEALED_STATUS.json",
            ),
        )
        self.assertEqual(
            parsed.published_unledgered_record_path,
            "evidence/release-operations/v4.4.1/UNSEALED_STATUS.json",
        )

    def test_project_status_v3_schema_pins_direct_record_and_signature(
        self,
    ) -> None:
        status = _project_status_v3_fixture()
        schema = json.loads(
            (
                ROOT / "tests/status/project-status-v3.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        self.assertEqual(list(validator.iter_errors(status)), [])

        parsed = render_project_status.load_status(
            ROOT,
            raw=(json.dumps(status) + "\n").encode(),
        )
        self.assertEqual(parsed.schema_version, "evoguard-project-status-v3")
        self.assertEqual(parsed.lifecycle, "release-line")
        self.assertEqual(
            parsed.direct_release_record_path,
            "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json",
        )
        self.assertEqual(
            parsed.direct_release_record_sha256,
            status["published_release"]["record_sha256"],
        )
        self.assertEqual(
            parsed.direct_release_signature_path,
            "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json.sig",
        )
        self.assertEqual(
            parsed.direct_release_signature_sha256,
            status["published_release"]["signature_sha256"],
        )
        self.assertEqual(
            parsed.ledger_path,
            "evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json",
        )

        for lifecycle in (
            "unreleased-development",
            "release-candidate",
            "release-line",
        ):
            with self.subTest(lifecycle=lifecycle):
                candidate = json.loads(json.dumps(status))
                candidate["source"]["lifecycle"] = lifecycle
                self.assertEqual(list(validator.iter_errors(candidate)), [])
                parsed_candidate = render_project_status.load_status(
                    ROOT,
                    raw=(json.dumps(candidate) + "\n").encode(),
                )
                self.assertEqual(parsed_candidate.lifecycle, lifecycle)

        def schema_rejected(mutator: object) -> None:
            candidate = json.loads(json.dumps(status))
            assert callable(mutator)
            mutator(candidate)
            self.assertNotEqual(list(validator.iter_errors(candidate)), [])

        schema_mutations = (
            lambda value: value["source"].__setitem__(
                "lifecycle", "published-unledgered"
            ),
            lambda value: value["published_release"].__setitem__(
                "record", "evidence/release-ledgers/v4.7.1/RELEASE_LEDGER.json"
            ),
            lambda value: value["published_release"].__setitem__(
                "record_sha256", "A" * 64
            ),
            lambda value: value["published_release"].__setitem__(
                "signature",
                "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.sig",
            ),
            lambda value: value["published_release"].__setitem__(
                "signature_sha256", "0" * 63
            ),
            lambda value: value["historical_evidence"].__setitem__(
                "latest_validated_a_h_ledger", "README.md"
            ),
            lambda value: value["release_pipeline"].__setitem__(
                "implementation", "scaffolded"
            ),
            lambda value: value.__setitem__("unexpected", True),
        )
        for mutation in schema_mutations:
            with self.subTest(mutation=mutation):
                schema_rejected(mutation)

        mismatched = json.loads(json.dumps(status))
        mismatched["published_release"]["signature"] = (
            "evidence/direct-releases/v4.7.2/DIRECT_RELEASE.json.sig"
        )
        self.assertEqual(list(validator.iter_errors(mismatched)), [])
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status.load_status(
                ROOT,
                raw=(json.dumps(mismatched) + "\n").encode(),
            )

    def test_v471_uses_a_direct_record_without_fabricated_ledger_exception(
        self,
    ) -> None:
        self.assertTrue(
            (ROOT / "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json").is_file()
        )
        self.assertTrue(
            (
                ROOT
                / "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json.sig"
            ).is_file()
        )
        self.assertFalse(
            (ROOT / "evidence/release-ledgers/v4.7.1").exists(),
            "simple-release-v1 must not be misrepresented as an A-through-H ledger",
        )
        self.assertFalse(
            (ROOT / "evidence/release-operations/v4.7.1").exists(),
            "a successful publication must not receive an unsealed-status exception",
        )
        self.assertFalse(
            (ROOT / "docs/errata/V4.7.1-LEDGER.md").exists(),
            "no ledger erratum exists for a release that never claimed a ledger",
        )
        record = json.loads(
            (
                ROOT / "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json"
            ).read_text(encoding="utf-8")
        )
        schema = json.loads(
            (
                ROOT / "tests/status/direct-release-record-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        self.assertEqual(
            list(Draft202012Validator(schema).iter_errors(record)),
            [],
        )
        self.assertFalse(record["historical_evidence"]["applies_to_this_release"])
        self.assertTrue(record["trust_boundary"]["same_owner_operation"])
        self.assertFalse(record["trust_boundary"]["independent_review"])
        self.assertIn("not a release ledger", record["record_scope"])

    def test_direct_release_record_signature_and_cross_bindings_fail_closed(
        self,
    ) -> None:
        status = render_project_status.load_status(
            ROOT,
            raw=(json.dumps(_project_status_v3_fixture()) + "\n").encode(),
        )
        release = render_project_status._load_direct_release(
            ROOT,
            status,
            "4.7.1",
            verify_git=False,
        )
        self.assertEqual(release.version, "4.7.1")
        self.assertEqual(release.tag, "v4.7.1")
        self.assertEqual(
            release.commit_sha,
            "b222c7df0a3eaef6e89287cd1354625b88ac8b8b",
        )
        self.assertEqual(
            release.artifacts,
            ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"),
        )
        self.assertEqual(release.build_signer_workflow, ".github/workflows/release.yml")
        self.assertEqual(release.build_provenance_subjects, ("evo-guard.pyz",))
        self.assertEqual(release.sbom_subjects, ("evo-guard.pyz",))
        self.assertEqual(release.release_attestation_subjects, release.artifacts)
        development_release = render_project_status._load_direct_release(
            ROOT,
            replace(status, lifecycle="unreleased-development"),
            "4.8.0.dev0",
            verify_git=False,
        )
        self.assertEqual(development_release, release)
        with self.assertRaisesRegex(
            render_project_status.ProjectStatusError,
            "release-line source version must equal the direct release",
        ):
            render_project_status._load_direct_release(
                ROOT,
                status,
                "4.8.0",
                verify_git=False,
            )

        future_release_spec = replace(
            render_project_status._RELEASE_SPEC,
            path=".github/workflows/future-release.yml",
            reviewed_sha256="0" * 64,
        )
        with (
            mock.patch.object(
                render_project_status,
                "_RELEASE_SPEC",
                future_release_spec,
            ),
            mock.patch.object(
                render_project_status,
                "_RELEASE_PUBLISHED_VERIFY_PATH",
                ".github/workflows/future-release-verify.yml",
            ),
            mock.patch.object(
                render_project_status,
                "_RELEASE_PUBLISHED_VERIFY_SHA256",
                "1" * 64,
            ),
        ):
            historical = render_project_status._load_direct_release(
                ROOT,
                status,
                "4.7.1",
                verify_git=False,
            )
            with render_project_status._trusted_git_session(ROOT):
                trusted_head = render_project_status._git(
                    ROOT,
                    "rev-parse",
                    "--verify",
                    "HEAD",
                )
                historical_with_git = render_project_status._load_direct_release(
                    ROOT,
                    status,
                    "4.7.1",
                    verify_git=True,
                    trusted_head=trusted_head,
                )
        self.assertEqual(historical, release)
        self.assertEqual(historical_with_git, release)
        with (
            mock.patch.object(
                render_project_status,
                "_DIRECT_RELEASE_WORKFLOW_CONTRACTS",
                {},
            ),
            self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "workflow contract is not reviewed",
            ),
        ):
            render_project_status._load_direct_release(
                ROOT,
                status,
                "4.7.1",
                verify_git=False,
            )

        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._load_direct_release(
                ROOT,
                replace(status, direct_release_record_sha256="0" * 64),
                "4.7.1",
                verify_git=False,
            )
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._load_direct_release(
                ROOT,
                replace(status, direct_release_signature_sha256="0" * 64),
                "4.7.1",
                verify_git=False,
            )

        source_record = json.loads(
            (
                ROOT / "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json"
            ).read_text(encoding="utf-8")
        )
        source_signature = (
            ROOT / "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json.sig"
        ).read_bytes()
        authority_paths = (
            "security/release-maintainer-roots/v4.7.0.pub",
            "security/release-maintainer-roots/v4.7.0.json",
        )

        def seed(
            root: Path,
            record: dict[str, object],
            *,
            signature: bytes = source_signature,
        ) -> render_project_status.Status:
            record_bytes = (json.dumps(record, indent=2) + "\n").encode()
            for relative, contents in (
                (status.direct_release_record_path, record_bytes),
                (status.direct_release_signature_path, signature),
                *((relative, (ROOT / relative).read_bytes()) for relative in authority_paths),
            ):
                assert relative is not None
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents)
            return replace(
                status,
                direct_release_record_sha256=hashlib.sha256(record_bytes).hexdigest(),
                direct_release_signature_sha256=hashlib.sha256(signature).hexdigest(),
            )

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            mutated_signature = source_signature[:-1] + bytes(
                [source_signature[-1] ^ 1]
            )
            mutated_status = seed(
                root,
                source_record,
                signature=mutated_signature,
            )
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status._load_direct_release(
                    root,
                    mutated_status,
                    "4.7.1",
                    verify_git=False,
                )

        mutations = (
            (
                "record schema",
                lambda value: value.__setitem__("schema_version", "wrong"),
            ),
            (
                "record extra key",
                lambda value: value.__setitem__("independent", True),
            ),
            (
                "record timestamp",
                lambda value: value.__setitem__(
                    "recorded_utc", "2026-02-31T00:00:00Z"
                ),
            ),
            (
                "signature purpose",
                lambda value: value["maintainer_signature_contract"].__setitem__(
                    "purpose", "Independent release proof."
                ),
            ),
            (
                "signature identity",
                lambda value: value["maintainer_signature_contract"].__setitem__(
                    "identity", "github-actions[bot]"
                ),
            ),
            (
                "signature namespace",
                lambda value: value["maintainer_signature_contract"].__setitem__(
                    "namespace", "file"
                ),
            ),
            (
                "source version",
                lambda value: value["source"].__setitem__("version", "4.7.2"),
            ),
            (
                "source commit",
                lambda value: value["source"].__setitem__("commit_sha", "0" * 40),
            ),
            (
                "tag target",
                lambda value: value["tag"].__setitem__("target_sha", "0" * 40),
            ),
            (
                "tag verification",
                lambda value: value["tag"]["github_verification"].__setitem__(
                    "verified", False
                ),
            ),
            (
                "tag signing fingerprint",
                lambda value: value["tag"].__setitem__(
                    "maintainer_key_fingerprint", "SHA256:" + "A" * 43
                ),
            ),
            (
                "release state",
                lambda value: value["release"].__setitem__("immutable", False),
            ),
            (
                "release body semantics",
                lambda value: value["release"].__setitem__(
                    "body_sha256_semantics", "SHA-256 of raw body text."
                ),
            ),
            (
                "asset order",
                lambda value: value["assets"].reverse(),
            ),
            (
                "asset id uniqueness",
                lambda value: value["assets"][1].__setitem__(
                    "asset_id", value["assets"][0]["asset_id"]
                ),
            ),
            (
                "job identity",
                lambda value: value["workflow"]["jobs"][0].__setitem__(
                    "name", "publish-release"
                ),
            ),
            (
                "job id uniqueness",
                lambda value: value["workflow"]["jobs"][1].__setitem__(
                    "job_id", value["workflow"]["jobs"][0]["job_id"]
                ),
            ),
            (
                "workflow digest",
                lambda value: value["workflow"].__setitem__(
                    "workflow_sha256", "0" * 64
                ),
            ),
            (
                "workflow path",
                lambda value: value["workflow"].__setitem__(
                    "workflow_path", ".github/workflows/future-release.yml"
                ),
            ),
            (
                "verifier digest",
                lambda value: value["workflow"].__setitem__(
                    "verifier_sha256", "0" * 64
                ),
            ),
            (
                "verifier path",
                lambda value: value["workflow"].__setitem__(
                    "verifier_path",
                    ".github/workflows/future-release-published-verify.yml",
                ),
            ),
            (
                "workflow source",
                lambda value: value["workflow"].__setitem__("head_sha", "0" * 40),
            ),
            (
                "readback assets",
                lambda value: value["verification_observations"][
                    "post_publication_byte_readback"
                ]["asset_ids"].reverse(),
            ),
            (
                "SHA256SUMS asset digest",
                lambda value: (
                    value["assets"][2].__setitem__("sha256", "1" * 64),
                    value["verification_observations"][
                        "post_publication_byte_readback"
                    ]["asset_sha256"].__setitem__(2, "1" * 64),
                ),
            ),
            (
                "historical applicability",
                lambda value: value["historical_evidence"].__setitem__(
                    "applies_to_this_release", True
                ),
            ),
            (
                "same-owner boundary",
                lambda value: value["trust_boundary"].__setitem__(
                    "same_owner_operation", False
                ),
            ),
            (
                "independence boundary",
                lambda value: value["trust_boundary"].__setitem__(
                    "independent_review", True
                ),
            ),
            (
                "nonclaims",
                lambda value: value["trust_boundary"]["non_claims"].pop(),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), TemporaryDirectory() as temporary:
                root = Path(temporary)
                candidate = json.loads(json.dumps(source_record))
                mutate(candidate)
                mutated_status = seed(root, candidate)
                with (
                    mock.patch.object(
                        render_project_status,
                        "_verify_direct_release_signature",
                    ),
                    mock.patch.object(
                        render_project_status,
                        "_ssh_public_key_fingerprint",
                        return_value=(
                            "SHA256:iCn7wa6HgKdu7luf/16rrKZzSk5FygJoA8EKNl3LJ24"
                        ),
                    ),
                    self.assertRaises(render_project_status.ProjectStatusError),
                ):
                    render_project_status._load_direct_release(
                        root,
                        mutated_status,
                        "4.7.1",
                        verify_git=False,
                    )

    def test_direct_release_authority_bounds_precede_signature_subprocess(
        self,
    ) -> None:
        status = render_project_status.load_status(ROOT)
        source_signature = (
            ROOT / "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json.sig"
        ).read_bytes()
        cases = (
            (
                "record",
                b"x" * (render_project_status._MAX_DIRECT_RELEASE_RECORD_BYTES + 1),
                source_signature,
            ),
            (
                "signature",
                b"{}\n",
                b"x" * (
                    render_project_status._MAX_DIRECT_RELEASE_SIGNATURE_BYTES + 1
                ),
            ),
        )
        for label, record_bytes, signature_bytes in cases:
            with self.subTest(label=label), TemporaryDirectory() as temporary:
                root = Path(temporary)
                for relative, contents in (
                    (status.direct_release_record_path, record_bytes),
                    (status.direct_release_signature_path, signature_bytes),
                ):
                    assert relative is not None
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(contents)
                candidate = replace(
                    status,
                    direct_release_record_sha256=hashlib.sha256(
                        record_bytes
                    ).hexdigest(),
                    direct_release_signature_sha256=hashlib.sha256(
                        signature_bytes
                    ).hexdigest(),
                )
                with (
                    mock.patch.object(
                        render_project_status,
                        "_verify_direct_release_signature",
                    ) as verifier,
                    self.assertRaises(render_project_status.ProjectStatusError),
                ):
                    render_project_status._load_direct_release(
                        root,
                        candidate,
                        "4.7.1",
                        verify_git=False,
                    )
                verifier.assert_not_called()

    def test_direct_release_signature_uses_only_a_trusted_host_tool_environment(
        self,
    ) -> None:
        executable_name = "ssh-keygen.exe" if os.name == "nt" else "ssh-keygen"
        for parent in (ROOT, Path(os.environ.get("TEMP", str(ROOT)))):
            with self.subTest(parent=parent), TemporaryDirectory(dir=parent) as temporary:
                tool_directory = Path(temporary)
                fake = tool_directory / executable_name
                fake.write_bytes(b"malicious\n")
                if os.name != "nt":
                    fake.chmod(0o755)
                with (
                    mock.patch.dict(os.environ, {"PATH": str(tool_directory)}),
                    self.assertRaises(render_project_status.ProjectStatusError),
                ):
                    render_project_status._resolve_host_tool(ROOT, "ssh-keygen")

        trusted = render_project_status._resolve_host_tool(ROOT, "ssh-keygen")
        record_bytes = (
            ROOT / "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json"
        ).read_bytes()
        signature_bytes = (
            ROOT / "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json.sig"
        ).read_bytes()
        public_key_bytes = (
            ROOT / "security/release-maintainer-roots/v4.7.0.pub"
        ).read_bytes()
        completed = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        with (
            mock.patch.dict(
                os.environ,
                {"EVOGUARD_UNTRUSTED_SECRET": "must-not-propagate"},
            ),
            mock.patch.object(
                render_project_status,
                "_resolve_host_tool",
                return_value=trusted,
            ),
            mock.patch.object(render_project_status, "_require_host_tool_unchanged"),
            mock.patch.object(
                render_project_status.subprocess,
                "run",
                return_value=completed,
            ) as runner,
        ):
            render_project_status._verify_direct_release_signature(
                ROOT,
                record_bytes,
                signature_bytes,
                public_key_bytes,
            )
        environment = runner.call_args.kwargs["env"]
        self.assertNotIn("EVOGUARD_UNTRUSTED_SECRET", environment)
        self.assertEqual(environment["PATH"], trusted.search_path)
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertEqual(environment["LANG"], "C")
        self.assertLessEqual(
            set(environment),
            {
                "PATHEXT",
                "SystemRoot",
                "SYSTEMROOT",
                "WINDIR",
                "COMSPEC",
                "TEMP",
                "TMP",
                "PROGRAMDATA",
                "ProgramData",
                "PATH",
                "LC_ALL",
                "LANG",
            },
        )

    def test_direct_release_git_binding_rejects_tag_object_or_target_drift(
        self,
    ) -> None:
        status = render_project_status.load_status(ROOT)
        release = render_project_status._load_direct_release(
            ROOT,
            status,
            "4.7.1",
            verify_git=False,
        )
        public_key_bytes = (
            ROOT / "security/release-maintainer-roots/v4.7.0.pub"
        ).read_bytes()
        record = json.loads(
            (
                ROOT / "evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json"
            ).read_text(encoding="utf-8")
        )
        workflow = record["workflow"]
        git_identity = (
            "",
            release.tag_object_sha,
            "tag",
            release.commit_sha,
            release.tree_sha,
        )
        for label, candidate in (
            ("tag object", replace(release, tag_object_sha="0" * 40)),
            ("tag target", replace(release, commit_sha="0" * 40)),
        ):
            with (
                self.subTest(label=label),
                mock.patch.object(
                    render_project_status,
                    "_git",
                    side_effect=git_identity,
                ),
                mock.patch.object(
                    render_project_status,
                    "_resolve_host_tool",
                ) as resolver,
                self.assertRaises(render_project_status.ProjectStatusError),
            ):
                render_project_status._verify_direct_release_git_bindings(
                    ROOT,
                    candidate,
                    trusted_head="f" * 40,
                    public_key_bytes=public_key_bytes,
                    workflow_blob_sha=workflow["workflow_blob_sha"],
                    workflow_sha256=workflow["workflow_sha256"],
                    verifier_blob_sha=workflow["verifier_blob_sha"],
                    verifier_sha256=workflow["verifier_sha256"],
                )
            resolver.assert_not_called()

    def test_project_status_v2_authority_list_fails_closed(self) -> None:
        source = _project_status_v2_fixture()

        def rejected(mutator: object) -> None:
            candidate = json.loads(json.dumps(source))
            assert callable(mutator)
            mutator(candidate)
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status.load_status(
                    ROOT,
                    raw=(json.dumps(candidate) + "\n").encode(),
                )

        rejected(
            lambda value: value["release_exceptions"].__setitem__(
                "published_unledgered",
                list(
                    reversed(
                        value["release_exceptions"]["published_unledgered"]
                    )
                ),
            )
        )
        rejected(
            lambda value: value["release_exceptions"][
                "published_unledgered"
            ][1].__setitem__(
                "record_sha256",
                value["release_exceptions"]["published_unledgered"][0][
                    "record_sha256"
                ],
            )
        )
        rejected(
            lambda value: value["release_exceptions"][
                "published_unledgered"
            ][1].__setitem__(
                "erratum",
                "docs/errata/V4.4.2-LEDGER.md",
            )
        )
        rejected(
            lambda value: value["release_exceptions"][
                "published_unledgered"
            ][1].__setitem__(
                "record",
                value["release_exceptions"]["published_unledgered"][0][
                    "record"
                ],
            )
        )
        rejected(
            lambda value: value["release_exceptions"][
                "published_unledgered"
            ][1].__setitem__("record_sha256", "A" * 64)
        )
        rejected(
            lambda value: value["release_exceptions"].__setitem__(
                "published_unledgered",
                [],
            )
        )
        rejected(
            lambda value: value["release_exceptions"].__setitem__(
                "published_unledgered",
                value["release_exceptions"]["published_unledgered"][0],
            )
        )

    def test_project_status_runs_in_matrix_and_has_one_aggregate_check(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

        def assert_contract(candidate: str) -> None:
            jobs = render_project_status._parse_workflow_jobs(  # noqa: SLF001
                candidate,
                ".github/workflows/ci.yml",
            )
            test_block = re.search(
                r"(?ms)^  test:\s*\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*\n|\Z)",
                candidate,
            )
            aggregate_block = re.search(
                r"(?ms)^  project-status:\s*\n"
                r"(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*\n|\Z)",
                candidate,
            )
            self.assertIsNotNone(test_block)
            self.assertIsNotNone(aggregate_block)
            assert test_block is not None
            assert aggregate_block is not None
            self.assertRegex(
                test_block.group("body"),
                r'(?m)^\s{8}python-version:\s*\["3\.10", "3\.11", "3\.12"\]\s*$',
            )
            self.assertIn(
                "run: python -I ops/render_project_status.py --check",
                jobs["test"].active_text,
            )
            status_steps = list(
                re.finditer(
                    r"(?m)^      - name: Verify project status against source, "
                    r"ledger, workflows, and Git[ \t]*$\n"
                    r"(?P<body>(?:        [^\n]*\n)*)",
                    test_block.group("body"),
                )
            )
            self.assertEqual(len(status_steps), 1)
            self.assertEqual(
                status_steps[0].group("body"),
                "        run: python -I ops/render_project_status.py --check\n",
            )
            self.assertNotRegex(
                test_block.group("body"),
                r"(?m)^    continue-on-error:",
            )
            aggregate = jobs["project-status"]
            self.assertEqual(aggregate.needs, frozenset({"test"}))
            self.assertEqual(aggregate.gate, "always()")
            self.assertEqual(
                aggregate_block.group("body").rstrip(),
                (
                    "    if: always()\n"
                    "    needs: [test]\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - name: Aggregate matrix project-status result\n"
                    "        env:\n"
                    "          MATRIX_RESULT: ${{ needs.test.result }}\n"
                    '        run: test "$MATRIX_RESULT" = "success"'
                ),
            )

        assert_contract(workflow)
        command = "        run: python -I ops/render_project_status.py --check"
        for replacement in (
            "        # run: python -I ops/render_project_status.py --check",
            (
                '        run: echo "run: python -I '
                'ops/render_project_status.py --check"'
            ),
            (
                "        if: ${{ false }}\n"
                "        run: python -I ops/render_project_status.py --check"
            ),
            (
                "        continue-on-error: true\n"
                "        run: python -I ops/render_project_status.py --check"
            ),
            "",
        ):
            mutated = workflow.replace(command, replacement, 1)
            self.assertNotEqual(mutated, workflow)
            with self.subTest(replacement=replacement), self.assertRaises(
                AssertionError
            ):
                assert_contract(mutated)
        aggregate_bypass = workflow.replace(
            '        run: test "$MATRIX_RESULT" = "success"',
            "        run: true",
            1,
        )
        self.assertNotEqual(aggregate_bypass, workflow)
        with self.assertRaises(AssertionError):
            assert_contract(aggregate_bypass)

    def test_source_release_and_pipeline_semantics_are_consistent(self) -> None:
        context = render_project_status.load_context(ROOT, verify_git=False)
        self.assertEqual(
            (context.status.lifecycle, context.source_version),
            ("unreleased-development", "4.8.0.dev0"),
        )
        self.assertEqual(context.status.schema_version, "evoguard-project-status-v3")
        self.assertEqual(context.status.relation, "descendant")
        self.assertEqual(
            context.status.ledger_path,
            "evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json",
        )
        self.assertEqual(context.ledger.version, "4.6.0")
        self.assertEqual(context.ledger.tag, "v4.6.0")
        self.assertEqual(
            context.ledger.artifacts,
            ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"),
        )
        self.assertTrue(context.ledger.release_attestation_recorded)
        self.assertTrue(context.ledger.build_provenance_recorded)
        self.assertEqual(
            context.ledger.build_provenance_subjects,
            ("evo-guard.pyz",),
        )
        self.assertEqual(
            context.ledger.release_attestation_subjects,
            context.ledger.artifacts,
        )
        self.assertEqual(
            context.ledger.schema_version,
            "evoguard-release-ledger-v2",
        )
        self.assertTrue(context.ledger.sbom_recorded)
        self.assertTrue(context.ledger.pipeline_operational_evidence_recorded)
        self.assertTrue(context.ledger.pipeline_publication_evidence_recorded)
        self.assertIsNotNone(context.direct_release)
        assert context.direct_release is not None
        self.assertEqual(context.direct_release.version, "4.7.1")
        self.assertEqual(context.direct_release.tag, "v4.7.1")
        self.assertEqual(
            context.direct_release.commit_sha,
            "b222c7df0a3eaef6e89287cd1354625b88ac8b8b",
        )
        self.assertEqual(context.direct_release.artifacts, context.ledger.artifacts)
        self.assertEqual(
            context.direct_release.build_signer_workflow,
            ".github/workflows/release.yml",
        )
        self.assertEqual(
            context.direct_release.release_attestation_subjects,
            context.direct_release.artifacts,
        )
        self.assertEqual(
            context.direct_release.build_provenance_subjects,
            ("evo-guard.pyz",),
        )
        self.assertEqual(context.direct_release.sbom_subjects, ("evo-guard.pyz",))
        self.assertEqual(context.status.cli_extraction, "complete")
        generated = render_project_status._blocks(context)
        attestation_scope = " ".join(
            generated["README_ATTESTATION_SCOPE"].split()
        )
        evidence_row = " ".join(
            generated["PROJECT_STATUS_RELEASE_EVIDENCE_ROWS"].split()
        )
        self.assertIn(
            "build-provenance and SBOM subjects are both `evo-guard.pyz`",
            attestation_scope,
        )
        self.assertIn(
            "release-attestation verification binds `evo-guard.pyz`, "
            "`evo-guard.spdx.json`, `SHA256SUMS`",
            attestation_scope,
        )
        self.assertNotIn(
            "build provenance for its release artifacts",
            attestation_scope,
        )
        self.assertIn(
            "release-attestation verification binds `evo-guard.pyz`, "
            "`evo-guard.spdx.json`, `SHA256SUMS`",
            evidence_row,
        )
        self.assertIn(
            "build-provenance and SBOM subjects `evo-guard.pyz`",
            evidence_row,
        )
        self.assertIn("not a release ledger", attestation_scope)
        self.assertIn("same-owner observations", evidence_row)

    def test_project_status_v3_source_relations_preserve_consumer_authority(
        self,
    ) -> None:
        context = render_project_status.load_context(ROOT, verify_git=False)
        direct = context.direct_release
        self.assertIsNotNone(direct)
        assert direct is not None

        valid = (
            ("unreleased-development", "4.8.0.dev0", "unreleased development"),
            ("release-candidate", "4.8.0", "release candidate"),
            ("release-line", direct.version, "maintained direct release line"),
        )
        for lifecycle, source_version, rendered_truth in valid:
            with self.subTest(lifecycle=lifecycle):
                candidate = replace(
                    context,
                    source_version=source_version,
                    status=replace(context.status, lifecycle=lifecycle),
                )
                render_project_status._verify_source_relation(
                    candidate.status,
                    candidate.ledger,
                    candidate.source_version,
                    direct,
                )
                summary = render_project_status._release_summary(candidate)
                normalized_summary = " ".join(summary.split())
                self.assertIn(rendered_truth, normalized_summary)
                self.assertIn(
                    "latest immutable consumer release",
                    normalized_summary,
                )
                self.assertIn("[`v4.7.1`]", normalized_summary)

        invalid = (
            ("unreleased-development", "4.7.1.dev0", direct),
            ("unreleased-development", "4.7.0.dev0", direct),
            ("release-candidate", "4.7.1", direct),
            ("release-line", "4.8.0", direct),
            ("published-unledgered", "4.8.0", direct),
            ("unreleased-development", "4.8.0.dev0", None),
        )
        for lifecycle, source_version, authority in invalid:
            with self.subTest(lifecycle=lifecycle, source_version=source_version):
                with self.assertRaises(render_project_status.ProjectStatusError):
                    render_project_status._verify_source_relation(
                        replace(context.status, lifecycle=lifecycle),
                        context.ledger,
                        source_version,
                        authority,
                    )

        with self.assertRaisesRegex(
            render_project_status.ProjectStatusError,
            "historical ledger must precede the direct consumer release",
        ):
            render_project_status._verify_source_relation(
                context.status,
                replace(context.ledger, version=direct.version),
                context.source_version,
                direct,
            )

    def test_every_supported_status_enum_changes_rendered_truth(self) -> None:
        current = render_project_status.load_context(ROOT, verify_git=False)
        context = replace(
            current,
            status=_as_project_status_v2(current.status),
            direct_release=None,
        )
        development = replace(
            context,
            source_version="4.6.1.dev0",
            status=replace(
                context.status,
                lifecycle="unreleased-development",
            ),
        )
        render_project_status._verify_source_relation(
            development.status,
            development.ledger,
            development.source_version,
        )
        development_summary = render_project_status._release_summary(
            development
        )
        self.assertIn("unreleased development", development_summary)
        self.assertNotIn("release candidate", development_summary)

        candidate = replace(
            context,
            source_version="4.6.1",
            status=replace(context.status, lifecycle="release-candidate"),
        )
        render_project_status._verify_source_relation(
            candidate.status,
            candidate.ledger,
            candidate.source_version,
        )
        candidate_summary = render_project_status._release_summary(candidate)
        self.assertIn("release candidate", candidate_summary)
        self.assertNotIn("unreleased development", candidate_summary)
        published_unledgered = replace(
            context,
            source_version="4.6.1",
            status=replace(
                context.status,
                lifecycle="published-unledgered",
            ),
        )
        render_project_status._verify_source_relation(
            published_unledgered.status,
            published_unledgered.ledger,
            published_unledgered.source_version,
        )
        published_summary = " ".join(
            render_project_status._release_summary(published_unledgered).split()
        )
        self.assertIn("published stable GitHub release", published_summary)
        self.assertIn(
            "has no valid protected-tree release ledger",
            published_summary,
        )
        self.assertIn("not a signed ledger", published_summary)
        self.assertIn(
            "does not imply that a ledger for this version can be issued later",
            published_summary,
        )
        self.assertIn(
            "latest immutable consumer release recorded by the protected source tree",
            published_summary,
        )
        release_line = replace(
            context,
            source_version=context.ledger.version,
            status=replace(context.status, lifecycle="release-line"),
        )
        render_project_status._verify_source_relation(
            release_line.status,
            release_line.ledger,
            release_line.source_version,
        )
        self.assertIn(
            "ledger-recorded release line",
            render_project_status._release_summary(release_line),
        )
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._verify_source_relation(
                replace(context.status, lifecycle="release-candidate"),
                context.ledger,
                context.ledger.version,
            )
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._verify_source_relation(
                replace(context.status, lifecycle="published-unledgered"),
                context.ledger,
                context.ledger.version,
            )

        summary = render_project_status._pipeline_summary(
            replace(
                context,
                status=replace(
                    context.status,
                    pipeline_implementation="scaffolded",
                ),
            )
        )
        self.assertIn("not implementation-complete", " ".join(summary.split()))

        recorded = replace(
            context,
            ledger=replace(
                context.ledger,
                schema_version="evoguard-release-ledger-v2",
                artifacts=(
                    "evo-guard.pyz",
                    "evo-guard.spdx.json",
                    "SHA256SUMS",
                ),
                build_signer_workflow=(
                    ".github/workflows/evoguard-build-release-artifact.yml"
                ),
                release_attestation_subjects=(
                    "evo-guard.pyz",
                    "evo-guard.spdx.json",
                    "SHA256SUMS",
                ),
                sbom_recorded=True,
                pipeline_operational_evidence_recorded=True,
                pipeline_publication_evidence_recorded=True,
            ),
        )
        pipeline = " ".join(
            render_project_status._pipeline_summary(recorded).split()
        )
        release = " ".join(
            render_project_status._release_summary(recorded).split()
        )
        self.assertIn("signed v2 ledger records a completed", pipeline)
        self.assertIn("records the resulting publication", pipeline)
        self.assertIn("SPDX SBOM release asset", release)
        self.assertIn(
            "latest immutable consumer release recorded by the protected source tree",
            release,
        )
        generated = render_project_status._blocks(recorded)
        verification = generated["ATTESTATIONS_CONSUMER_VERIFICATION"]
        self.assertIn("--pattern evo-guard.spdx.json", verification)
        self.assertIn(
            "EvoRiseKsa/EvoOM-Guard-m/.github/workflows/"
            "evoguard-build-release-artifact.yml",
            verification,
        )
        self.assertIn("SPDX SBOM provenance", verification)
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._pipeline_summary(
                replace(
                    context,
                    status=replace(context.status, pipeline_implementation="unknown"),
                )
            )
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._release_summary(
                replace(
                    context,
                    status=replace(context.status, lifecycle="unknown"),
                )
            )

    def test_development_source_uses_direct_record_and_preserves_recovery_history(
        self,
    ) -> None:
        context = render_project_status.load_context(ROOT, verify_git=False)
        self.assertEqual(
            (context.status.lifecycle, context.source_version),
            ("unreleased-development", "4.8.0.dev0"),
        )
        self.assertEqual(context.ledger.version, "4.6.0")
        self.assertIsNotNone(context.direct_release)
        assert context.direct_release is not None
        self.assertEqual(context.direct_release.version, "4.7.1")
        self.assertEqual(
            tuple(
                release.version
                for release in context.published_unledgered_history
            ),
            ("4.4.0", "4.4.1"),
        )
        self.assertEqual(context.published_unledgered.version, "4.4.1")
        self.assertEqual(context.published_unledgered.recovery_version, "4.4.2")
        historical_exception = render_project_status._load_published_unledgered(
            ROOT,
            context.status,
            context.ledger,
            context.source_version,
            verify_git=False,
        )
        self.assertEqual(historical_exception.version, "4.4.1")

        blocks = render_project_status._blocks(context)
        pin_blocks = (
            "README_QUICKSTART_PIN",
            "README_INIT_PIN",
            "README_ACTION_PIN",
            "RELEASE_STATUS_CONSUMER_PIN",
            "ADOPTION_CURRENT_RELEASE",
            "GUARD_ACTION_EXAMPLE",
            "GUARD_NO_ACTION_EXAMPLE",
            "EVIDENCE_BUNDLES_RELEASE_PIN",
            "SIGNED_VERDICTS_RELEASE_PIN",
            "TRUSTED_FINALIZER_RELEASE_PIN",
        )
        for block in pin_blocks:
            with self.subTest(block=block):
                rendered = blocks[block]
                self.assertIn("v4.7.1", rendered)
                self.assertNotIn("v4.3.0", rendered)
                self.assertNotRegex(rendered, r"(?:@|--ref\s+)v4\.4\.[012]\b")

        pipeline = " ".join(
            blocks["PROJECT_STATUS_RELEASE_PIPELINE"].split()
        )
        self.assertIn(
            "detached-maintainer-signed direct record for `v4.7.1` records successful",
            pipeline,
        )
        self.assertIn(
            "same-owner observation, not independent validation",
            pipeline,
        )
        support = blocks["SECURITY_SUPPORTED_VERSIONS"]
        self.assertIn(
            "Latest stable release; supported",
            support,
        )
        self.assertIn("[`v4.7.1`]", support)
        self.assertIn("[`v4.6.0`]", support)
        self.assertIn("`4.8.0.dev0`", support)
        self.assertIn("Unreleased development source", support)
        self.assertIn("Historical latest validated A-through-H ledger", support)
        self.assertNotIn("temporarily supported", support)
        self.assertNotIn("recovery successor", support)

    def test_v440_unsealed_status_is_explicitly_not_a_release_ledger(self) -> None:
        record_path = (
            ROOT
            / "evidence"
            / "release-operations"
            / "v4.4.0"
            / "UNSEALED_STATUS.json"
        )
        record = json.loads(record_path.read_text(encoding="utf-8"))
        release = record["release"]
        self.assertEqual(
            record["schema_version"],
            "evoguard-unsealed-release-status-v1",
        )
        self.assertIn("not a release ledger", record["record_scope"])
        self.assertEqual(release["version"], "4.4.0")
        self.assertEqual(release["tag"], "v4.4.0")
        self.assertEqual(
            release["commit_sha"],
            "5671282c3d2e97ea0d3c4f2b8f592f2405102f1f",
        )
        self.assertEqual(release["state"], "published")
        self.assertFalse(release["draft"])
        self.assertFalse(release["prerelease"])
        self.assertTrue(release["immutable"])
        self.assertEqual(release["created_utc"], "2026-07-29T01:30:39Z")
        self.assertIn("target-commit metadata", release["created_utc_semantics"])
        self.assertEqual(release["published_utc"], "2026-07-29T01:55:50Z")
        self.assertEqual(
            {
                asset["name"]: (asset["size"], asset["sha256"])
                for asset in record["assets"]
            },
            {
                "evo-guard.pyz": (
                    2210594,
                    "192157882cf9261e075116e559e92492124909b6268eff497542c4d27486f84b",
                ),
                "evo-guard.spdx.json": (
                    97884,
                    "4e3f0adc613065e4c2dbac20b6a87be9c4bd24d79d1c95b702fa23fcb4cb153b",
                ),
                "SHA256SUMS": (
                    166,
                    "17a242e0c6cce7ca1ee2f9d5bf26258c16c7c80803112f6e1fc3da9958ed0bd5",
                ),
            },
        )
        observations = record["verification_observations"]
        self.assertTrue(observations["release_attestation"]["verified"])
        self.assertTrue(observations["build_provenance"]["verified"])
        self.assertEqual(
            set(observations["build_provenance"]["subjects"]),
            {"evo-guard.pyz", "evo-guard.spdx.json"},
        )
        for run_name in ("tag_ci", "action_smoke"):
            with self.subTest(run=run_name):
                run = observations[run_name]
                self.assertEqual(run["conclusion"], "success")
                self.assertEqual(run["successful_jobs"], run["total_jobs"])
                self.assertEqual(run["total_jobs"], 8)
        failure = record["failure_boundary"]
        self.assertEqual(
            failure["reason_code"],
            "FROZEN_VALIDATOR_CREATED_AT_SEMANTICS_MISMATCH",
        )
        self.assertEqual(
            failure["trusted_parent_commit_sha"],
            "163ad0591ac64cada35f0643683f3afff397e2d6",
        )
        self.assertEqual(
            failure["trusted_parent_tree_sha"],
            "df5821ec364e9d62a77bf3ee609a575583ae351a",
        )
        self.assertEqual(
            failure["validator_blob_sha"],
            "d80180d7ce744fbc2f06dae44dce0718b2693fbf",
        )
        self.assertEqual(failure["h_run_id"], 30415174549)
        self.assertEqual(failure["h_run_attempt"], 1)
        self.assertLess(
            failure["release_created_utc"],
            failure["h_observed_window"]["started_utc"],
        )
        self.assertLessEqual(
            failure["h_observed_window"]["started_utc"],
            failure["release_published_utc"],
        )
        self.assertLessEqual(
            failure["release_published_utc"],
            failure["h_observed_window"]["completed_utc"],
        )
        self.assertTrue(failure["release_created_before_h"])
        self.assertTrue(failure["release_published_inside_h"])
        self.assertEqual(failure["corrected_semantics_pr"], 255)
        self.assertEqual(
            failure["corrected_semantics_commit"],
            "83c7bcff45cc710a791dd5d18f0c5075c9067495",
        )
        self.assertFalse(failure["retroactive_correction_allowed"])
        ledger_state = record["ledger_state"]
        self.assertFalse(ledger_state["sealed"])
        self.assertFalse(ledger_state["canonical_ledger_issued"])
        self.assertFalse(ledger_state["signature_issued"])
        self.assertFalse(ledger_state["v4_4_0_release_ledger_present"])
        self.assertEqual(
            ledger_state["reason_code"],
            "FROZEN_VALIDATOR_CREATED_AT_SEMANTICS_MISMATCH",
        )
        self.assertEqual(
            ledger_state["latest_validated_repository_ledger"],
            "tests/baseline/v4.3.0/RELEASE_LEDGER.json",
        )
        self.assertEqual(ledger_state["recovery_release"], "v4.4.1")
        self.assertFalse(
            (
                ROOT
                / "evidence"
                / "release-ledgers"
                / "v4.4.0"
                / "RELEASE_LEDGER.json"
            ).exists()
        )
        erratum = (
            ROOT / "docs" / "errata" / "V4.4.0-LEDGER.md"
        ).read_text(encoding="utf-8")
        self.assertIn("not** a release ledger", erratum)
        self.assertIn("UNSEALED_STATUS.json", erratum)
        self.assertIn(
            "Do not move `v4.4.0` or rewrite its release",
            erratum,
        )
        self.assertIn("Prepare `v4.4.1`", erratum)
        self.assertIn(
            "Keep `v4.4.0` permanently recorded",
            erratum,
        )
        self.assertNotIn(
            "Assemble and independently validate a truthful post-publication "
            "v2 ledger",
            erratum,
        )

    def test_ordered_history_accepts_v440_v1_and_synthetic_v441_v2(
        self,
    ) -> None:
        context = render_project_status.load_context(ROOT, verify_git=False)
        legacy_candidate_version = context.source_version.removesuffix(".dev0")
        source_v440 = json.loads(
            (
                ROOT
                / "evidence/release-operations/v4.4.0/UNSEALED_STATUS.json"
            ).read_text(encoding="utf-8")
        )
        source_disposition = json.loads(
            (
                ROOT
                / "evidence/release-operations/v4.4.0/"
                "LEDGER_KEY_DISPOSITION.json"
            ).read_text(encoding="utf-8")
        )

        def synthetic_v441() -> tuple[dict[str, object], dict[str, object]]:
            record = json.loads(json.dumps(source_v440))
            record["schema_version"] = "evoguard-unsealed-release-status-v2"
            record["recorded_utc"] = "2026-07-29T08:00:00Z"
            release = record["release"]
            release.update(
                {
                    "version": "4.4.1",
                    "tag": "v4.4.1",
                    "commit_sha": "2" * 40,
                    "release_id": 2,
                    "created_utc": "2026-07-29T07:00:00Z",
                    "published_utc": "2026-07-29T07:30:00Z",
                    "release_url": (
                        "https://github.com/EvoRiseKsa/EvoOM-Guard-m/"
                        "releases/tag/v4.4.1"
                    ),
                }
            )
            for asset in record["assets"]:
                asset["url"] = asset["url"].replace("v4.4.0", "v4.4.1")
            observations = record["verification_observations"]
            observations["release_attestation"].update(
                {
                    "tag_commit_sha": "2" * 40,
                    "command": (
                        "gh release verify v4.4.1 --repo "
                        "EvoRiseKsa/EvoOM-Guard-m"
                    ),
                }
            )
            observations["build_provenance"]["source_commit_sha"] = "2" * 40
            for name in ("tag_ci", "action_smoke"):
                observations[name]["head_sha"] = "2" * 40
            record["failure_boundary"] = {
                "reason_code": "FROZEN_VALIDATOR_CONTRACT_DEFECTS",
                "trusted_parent_commit_sha": "3" * 40,
                "trusted_parent_tree_sha": "4" * 40,
                "validator_path": "tools/ci/validate_release_ledger_v2.py",
                "validator_blob_sha": "5" * 40,
                "defects": [
                    {
                        "code": "TRUSTED_IMPORT_COLD_START_ALIAS_REJECTION",
                        "boundary": "trusted-import-cold-start",
                        "affected_material": [],
                        "observation": (
                            "The frozen validator rejects an original CPython "
                            "originless module alias during cold start."
                        ),
                    },
                    {
                        "code": "RETAINED_RESULT_JSON_ENCODING_MISMATCH",
                        "boundary": "retained-result-encoding",
                        "affected_material": [
                            {
                                "path": (
                                    "admission/source/"
                                    "protected-seal-result.json"
                                ),
                                "size_bytes": 530,
                                "sha256": "7" * 64,
                            }
                        ],
                        "observation": (
                            "The frozen validator requires compact JSON while "
                            "the frozen producer emits reviewed indented JSON."
                        ),
                    },
                ],
                "corrected_pr": 999,
                "corrected_commit": "6" * 40,
                "retroactive_correction_allowed": False,
                "explanation": (
                    "The release operation and descriptor are bound to the "
                    "frozen trusted parent and validator blob. Later corrections "
                    "cannot replace those inputs retroactively."
                ),
            }
            ledger_state = record["ledger_state"]
            ledger_state["v4_4_1_release_ledger_present"] = ledger_state.pop(
                "v4_4_0_release_ledger_present"
            )
            ledger_state["reason_code"] = (
                "FROZEN_VALIDATOR_CONTRACT_DEFECTS"
            )
            ledger_state["recovery_release"] = "v4.4.2"
            record["trust_boundary"][-2:] = [
                (
                    "The v4.4.1 tag, release assets, checksums, and "
                    "attestations must not be rewritten to repair the missing "
                    "ledger."
                ),
                (
                    "No canonical v4.4.1 ledger or ledger signature can be "
                    "issued retroactively after the frozen validator contract "
                    "has been corrected; recovery requires a new release."
                ),
            ]

            disposition = json.loads(json.dumps(source_disposition))
            disposition["release"].update(
                {
                    "version": "4.4.1",
                    "tag": "v4.4.1",
                    "reason_code": "FROZEN_VALIDATOR_CONTRACT_DEFECTS",
                }
            )
            disposition["key"].update(
                {
                    "purpose": (
                        "prospective v4.4.1 release-ledger signing only"
                    ),
                    "public_key_path": (
                        "security/release-ledger-roots/v4.4.1.pub.pem"
                    ),
                    "public_key_id": (
                        "sha256:"
                        "ab3501f94e2d5fe7e27d02c2d82957738c29102fb37c7150"
                        "0392f7f559342e6a"
                    ),
                    "private_file_basename": (
                        "release-ledger-v4.4.1.private.pem"
                    ),
                }
            )
            disposition["disposition"]["trigger"] = (
                "Canonical v4.4.1 ledger issuance is impossible under the "
                "frozen release validator; the unused operator-local "
                "private-key file has no remaining authorized signing purpose."
            )
            disposition["disposition"]["authorized_action"] = (
                "Remove only the named operator-local private-key file after "
                "independently confirming the v4.4.1 ledger failure boundary."
            )
            disposition["non_claims"][-1] = (
                "This record does not create, sign, validate, or repair a "
                "v4.4.1 release ledger."
            )
            return record, disposition

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "evidence/release-operations/v4.4.0/UNSEALED_STATUS.json",
                "evidence/release-operations/v4.4.0/"
                "LEDGER_KEY_DISPOSITION.json",
                "docs/errata/V4.4.0-LEDGER.md",
                "security/release-ledger-roots/v4.4.0.pub.pem",
                "security/release-ledger-roots/v4.4.1.pub.pem",
                "tests/baseline/v4.3.0/RELEASE_LEDGER.json",
                "evidence/release-ledgers/v4.4.2/RELEASE_LEDGER.json",
            ):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())

            record, disposition = synthetic_v441()
            record_path = (
                root
                / "evidence/release-operations/v4.4.1/"
                "UNSEALED_STATUS.json"
            )
            disposition_path = (
                root
                / "evidence/release-operations/v4.4.1/"
                "LEDGER_KEY_DISPOSITION.json"
            )
            erratum_path = root / "docs/errata/V4.4.1-LEDGER.md"
            record_path.parent.mkdir(parents=True, exist_ok=True)
            erratum_path.parent.mkdir(parents=True, exist_ok=True)
            record_bytes = (json.dumps(record, indent=2) + "\n").encode()
            record_path.write_bytes(record_bytes)
            disposition_path.write_text(
                json.dumps(disposition, indent=2) + "\n",
                encoding="utf-8",
            )
            erratum_path.write_bytes(
                b"# v4.4.1 release-ledger erratum\n\n"
                b"This is a post-publication correction record. It is **not** "
                b"a release ledger.\n\n"
                b"`evidence/release-operations/v4.4.1/UNSEALED_STATUS.json`\n\n"
                b"Prepare `v4.4.2` as a new release.\n"
            )

            status_value = _project_status_v2_fixture()
            status_value["release_exceptions"]["published_unledgered"][1][
                "record_sha256"
            ] = hashlib.sha256(record_bytes).hexdigest()
            status = render_project_status.load_status(
                root,
                raw=(json.dumps(status_value) + "\n").encode(),
            )
            history = tuple(
                render_project_status._load_published_unledgered(
                    root,
                    status,
                    context.ledger,
                    legacy_candidate_version,
                    verify_git=False,
                    authority=authority,
                    validate_relation=False,
                )
                for authority in status.published_unledgered_authorities
            )
            render_project_status._validate_published_unledgered_chain(
                root,
                status,
                context.ledger,
                legacy_candidate_version,
                history,
            )
            self.assertEqual(
                tuple(item.version for item in history),
                ("4.4.0", "4.4.1"),
            )
            self.assertEqual(history[-1].recovery_version, "4.4.2")

            skipped = replace(history[0], recovery_version="4.4.2")
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status._validate_published_unledgered_chain(
                    root,
                    status,
                    context.ledger,
                    legacy_candidate_version,
                    (skipped, history[1]),
                )

            failure_mutations = (
                (
                    "path traversal",
                    lambda value: value["failure_boundary"]["defects"][1][
                        "affected_material"
                    ][0].__setitem__("path", "../protected-seal-result.json"),
                ),
                (
                    "noncanonical digest",
                    lambda value: value["failure_boundary"]["defects"][1][
                        "affected_material"
                    ][0].__setitem__("sha256", "A" * 64),
                ),
                (
                    "duplicate defect",
                    lambda value: value["failure_boundary"]["defects"][
                        1
                    ].__setitem__(
                        "code",
                        value["failure_boundary"]["defects"][0]["code"],
                    ),
                ),
                (
                    "duplicate material path",
                    lambda value: value["failure_boundary"]["defects"][0][
                        "affected_material"
                    ].append(
                        json.loads(
                            json.dumps(
                                value["failure_boundary"]["defects"][1][
                                    "affected_material"
                                ][0]
                            )
                        )
                    ),
                ),
                (
                    "unexpected key",
                    lambda value: value["failure_boundary"]["defects"][0].__setitem__(
                        "unsupported",
                        True,
                    ),
                ),
            )
            for label, mutate in failure_mutations:
                with self.subTest(v2_failure_boundary=label):
                    candidate = json.loads(json.dumps(record))
                    mutate(candidate)
                    candidate_bytes = (
                        json.dumps(candidate, indent=2) + "\n"
                    ).encode()
                    record_path.write_bytes(candidate_bytes)
                    authority = replace(
                        status.published_unledgered_authorities[1],
                        record_sha256=hashlib.sha256(
                            candidate_bytes
                        ).hexdigest(),
                    )
                    with self.assertRaises(
                        render_project_status.ProjectStatusError
                    ):
                        render_project_status._load_published_unledgered(
                            root,
                            status,
                            context.ledger,
                            "4.4.2.dev0",
                            verify_git=False,
                            authority=authority,
                            validate_relation=False,
                        )

            record_path.write_bytes(record_bytes + b"\n")
            with self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "reviewed digest",
            ):
                render_project_status._load_published_unledgered(
                    root,
                    status,
                    context.ledger,
                    "4.4.2.dev0",
                    verify_git=False,
                    authority=status.published_unledgered_authorities[1],
                    validate_relation=False,
                )

    def test_published_unledgered_authority_fails_closed(self) -> None:
        context = render_project_status.load_context(ROOT, verify_git=False)

        def write_authority(
            root: Path,
            record: dict[str, object],
        ) -> render_project_status.Status:
            record_path = root / context.status.published_unledgered_record_path
            erratum_path = root / context.status.published_unledgered_erratum_path
            disposition_path = root / context.status.published_unledgered_key_disposition_path
            record_path.parent.mkdir(parents=True)
            erratum_path.parent.mkdir(parents=True)
            disposition_path.parent.mkdir(parents=True, exist_ok=True)
            record_bytes = (json.dumps(record, indent=2) + "\n").encode()
            record_path.write_bytes(record_bytes)
            erratum_path.write_bytes(
                (ROOT / context.status.published_unledgered_erratum_path).read_bytes()
            )
            disposition_path.write_bytes(
                (ROOT / context.status.published_unledgered_key_disposition_path).read_bytes()
            )
            public_key = root / "security/release-ledger-roots/v4.4.0.pub.pem"
            public_key.parent.mkdir(parents=True)
            public_key.write_bytes(
                (ROOT / "security/release-ledger-roots/v4.4.0.pub.pem").read_bytes()
            )
            observed_ledger = root / "tests/baseline/v4.3.0/RELEASE_LEDGER.json"
            observed_ledger.parent.mkdir(parents=True)
            observed_ledger.write_bytes(
                (ROOT / "tests/baseline/v4.3.0/RELEASE_LEDGER.json").read_bytes()
            )
            return replace(
                context.status,
                published_unledgered_record_sha256=hashlib.sha256(
                    record_bytes
                ).hexdigest(),
            )

        source_record = json.loads(
            (ROOT / context.status.published_unledgered_record_path).read_text(encoding="utf-8")
        )
        mutations = (
            lambda record: record["release"].__setitem__("immutable", False),
            lambda record: record["release"].__setitem__("state", "draft"),
            lambda record: record["ledger_state"].__setitem__(
                "canonical_ledger_issued",
                True,
            ),
            lambda record: record["ledger_state"].__setitem__(
                "signature_issued",
                True,
            ),
            lambda record: record["release"].__setitem__("version", "4.4.9"),
            lambda record: record["release"].__setitem__(
                "commit_sha",
                "not-a-sha",
            ),
            lambda record: record.__setitem__("assets", []),
            lambda record: record["ledger_state"].__setitem__(
                "reason_code",
                "DIFFERENT_REASON",
            ),
            lambda record: record["trust_boundary"].__setitem__(
                0,
                "This is canonical ledger evidence.",
            ),
            lambda record: record.__setitem__(
                "recorded_utc",
                "2026-02-31T00:00:00Z",
            ),
            lambda record: record["verification_observations"][
                "tag_ci"
            ].__setitem__("head_sha", "0" * 40),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), TemporaryDirectory() as temporary:
                root = Path(temporary)
                record = json.loads(json.dumps(source_record))
                mutate(record)
                mutated_status = write_authority(root, record)
                with self.assertRaises(render_project_status.ProjectStatusError):
                    render_project_status._load_published_unledgered(
                        root,
                        mutated_status,
                        context.ledger,
                        context.source_version,
                        verify_git=False,
                    )

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_status = write_authority(root, source_record)
            false_ledger = root / "evidence" / "release-ledgers" / "v4.4.0" / "RELEASE_LEDGER.json"
            false_ledger.parent.mkdir(parents=True)
            false_ledger.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status._load_published_unledgered(
                    root,
                    source_status,
                    context.ledger,
                    context.source_version,
                    verify_git=False,
                )

    def test_authority_json_parsers_use_the_verified_byte_snapshot(self) -> None:
        trusted_status_bytes = (ROOT / "PROJECT_STATUS.json").read_bytes()
        trusted_status = render_project_status.load_status(
            ROOT,
            raw=trusted_status_bytes,
        )
        attacker_lifecycle = (
            "release-candidate"
            if trusted_status.lifecycle != "release-candidate"
            else "unreleased-development"
        )
        trusted_assignment = f'"lifecycle": "{trusted_status.lifecycle}"'.encode()
        attacker_assignment = f'"lifecycle": "{attacker_lifecycle}"'.encode()
        self.assertEqual(trusted_status_bytes.count(trusted_assignment), 1)
        attacker_status_bytes = trusted_status_bytes.replace(
            trusted_assignment,
            attacker_assignment,
            1,
        )
        with mock.patch.object(
            Path,
            "read_bytes",
            return_value=attacker_status_bytes,
        ) as read_bytes:
            parsed = render_project_status.load_status(
                ROOT,
                raw=trusted_status_bytes,
            )
        read_bytes.assert_not_called()
        self.assertEqual(parsed.lifecycle, trusted_status.lifecycle)
        self.assertNotEqual(parsed.lifecycle, attacker_lifecycle)

        context = render_project_status.load_context(ROOT, verify_git=False)
        with mock.patch.object(
            render_project_status,
            "_load_json",
            side_effect=AssertionError("authority JSON was re-read"),
        ) as reread:
            authority = render_project_status._load_published_unledgered(
                ROOT,
                context.status,
                context.ledger,
                context.source_version,
                verify_git=False,
            )
        reread.assert_not_called()
        self.assertEqual(authority.version, "4.4.1")

    def test_unledgered_failure_boundary_is_derived_from_git(self) -> None:
        record = json.loads(
            (
                ROOT
                / "evidence/release-operations/v4.4.0/UNSEALED_STATUS.json"
            ).read_text(encoding="utf-8")
        )
        release = record["release"]
        boundary = record["failure_boundary"]
        arguments = {
            "tag": release["tag"],
            "release_commit": release["commit_sha"],
            "trusted_parent_commit": boundary["trusted_parent_commit_sha"],
            "trusted_parent_tree": boundary["trusted_parent_tree_sha"],
            "validator_path": boundary["validator_path"],
            "validator_blob": boundary["validator_blob_sha"],
            "corrected_commit": boundary["corrected_semantics_commit"],
            "corrected_pr": boundary["corrected_semantics_pr"],
        }
        with render_project_status._trusted_git_session(ROOT):
            trusted_head, trusted_exception_tag_commit = (
                render_project_status._git_ref_snapshot(
                    ROOT,
                    release["tag"],
                )
            )
            arguments |= {
                "trusted_head": trusted_head,
                "trusted_exception_tag_commit": trusted_exception_tag_commit,
            }
            render_project_status._verify_published_unledgered_git_bindings(
                ROOT,
                **arguments,
            )
            mutations = (
                {"trusted_head": "a" * 40},
                {"trusted_exception_tag_commit": "a" * 40},
                {"release_commit": "a" * 40},
                {"trusted_parent_commit": "a" * 40},
                {"trusted_parent_tree": "a" * 40},
                {"validator_blob": "a" * 40},
                {"corrected_commit": "a" * 40},
                {"corrected_pr": 999999},
            )
            for mutation in mutations:
                with self.subTest(mutation=mutation), self.assertRaises(
                    render_project_status.ProjectStatusError
                ):
                    render_project_status._verify_published_unledgered_git_bindings(
                        ROOT,
                        **(arguments | mutation),
                    )

    def test_final_authority_snapshots_close_late_replacement_windows(self) -> None:
        original_read = render_project_status._read_stable_bytes
        status_path = (ROOT / "PROJECT_STATUS.json").resolve()
        trusted_status_bytes = status_path.read_bytes()
        attacker_status = json.loads(trusted_status_bytes)
        attacker_status["source"]["lifecycle"] = "release-candidate"
        attacker_status_bytes = (json.dumps(attacker_status) + "\n").encode()
        status_reads = 0

        def replace_status_late(
            root: Path,
            path: Path,
        ) -> tuple[bytes, render_project_status._FileIdentity]:
            nonlocal status_reads
            raw, identity = original_read(root, path)
            if path.resolve() == status_path:
                status_reads += 1
                if status_reads >= 3:
                    return attacker_status_bytes, identity
            return raw, identity

        with (
            mock.patch.object(
                render_project_status,
                "_read_stable_bytes",
                side_effect=replace_status_late,
            ),
            mock.patch.object(render_project_status, "_verify_tracked_bytes"),
            mock.patch.object(render_project_status, "_verify_git"),
            self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "PROJECT_STATUS.json changed during validation",
            ),
        ):
            render_project_status._load_context_with_trusted_git(
                ROOT,
                verify_git=True,
            )

        context = render_project_status.load_context(ROOT, verify_git=False)
        latest_disposition = json.loads(
            (
                ROOT
                / context.status.published_unledgered_key_disposition_path
            ).read_text(encoding="utf-8")
        )
        public_key_path = (
            ROOT / latest_disposition["key"]["public_key_path"]
        ).resolve()
        public_key_reads = 0

        def replace_public_key_late(
            root: Path,
            path: Path,
        ) -> tuple[bytes, render_project_status._FileIdentity]:
            nonlocal public_key_reads
            raw, identity = original_read(root, path)
            if path.resolve() == public_key_path:
                public_key_reads += 1
                if public_key_reads >= 2:
                    return raw + b"late replacement", identity
            return raw, identity

        with (
            mock.patch.object(
                render_project_status,
                "_read_stable_bytes",
                side_effect=replace_public_key_late,
            ),
            self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "public key changed during validation",
            ),
        ):
            render_project_status._load_published_unledgered(
                ROOT,
                context.status,
                context.ledger,
                context.source_version,
                verify_git=False,
            )

        public_key_reads = 0

        def replace_public_key_in_outer_snapshot(
            root: Path,
            path: Path,
        ) -> tuple[bytes, render_project_status._FileIdentity]:
            nonlocal public_key_reads
            raw, identity = original_read(root, path)
            if path.resolve() == public_key_path:
                public_key_reads += 1
                if public_key_reads >= 3:
                    return raw + b"late outer replacement", identity
            return raw, identity

        with (
            mock.patch.object(
                render_project_status,
                "_read_stable_bytes",
                side_effect=replace_public_key_in_outer_snapshot,
            ),
            mock.patch.object(render_project_status, "_verify_tracked_bytes"),
            mock.patch.object(render_project_status, "_verify_git"),
            self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "authority changed during validation",
            ),
        ):
            render_project_status._load_context_with_trusted_git(
                ROOT,
                verify_git=True,
            )

        with render_project_status._trusted_git_session(ROOT):
            frozen_refs = render_project_status._git_refs_snapshot(
                ROOT,
                ("v4.4.0", "v4.4.1"),
            )
        with (
            mock.patch.object(
                render_project_status,
                "_git_refs_snapshot",
                side_effect=(frozen_refs, ("a" * 40, frozen_refs[1])),
            ),
            mock.patch.object(render_project_status, "_verify_tracked_bytes"),
            mock.patch.object(render_project_status, "_verify_git"),
            self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "Git references changed during validation",
            ),
        ):
            render_project_status._load_context_with_trusted_git(
                ROOT,
                verify_git=True,
            )

        original_direct_load = render_project_status._load_direct_release
        direct_loads = 0
        final_direct_returned = False

        def observe_direct_load(*args: object, **kwargs: object) -> object:
            nonlocal direct_loads, final_direct_returned
            result = original_direct_load(*args, **kwargs)
            direct_loads += 1
            if direct_loads >= 2:
                final_direct_returned = True
            return result

        def replace_status_after_final_direct(
            root: Path,
            path: Path,
        ) -> tuple[bytes, render_project_status._FileIdentity]:
            raw, identity = original_read(root, path)
            if final_direct_returned and path.resolve() == status_path:
                return attacker_status_bytes, identity
            return raw, identity

        with (
            mock.patch.object(
                render_project_status,
                "_load_direct_release",
                side_effect=observe_direct_load,
            ),
            mock.patch.object(
                render_project_status,
                "_read_stable_bytes",
                side_effect=replace_status_after_final_direct,
            ),
            mock.patch.object(render_project_status, "_verify_tracked_bytes"),
            mock.patch.object(render_project_status, "_verify_git"),
            mock.patch.object(render_project_status, "_verify_direct_release_signature"),
            mock.patch.object(
                render_project_status,
                "_verify_direct_release_git_bindings",
            ),
            mock.patch.object(
                render_project_status,
                "_ssh_public_key_fingerprint",
                return_value="SHA256:iCn7wa6HgKdu7luf/16rrKZzSk5FygJoA8EKNl3LJ24",
            ),
            self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "PROJECT_STATUS.json changed during validation",
            ),
        ):
            render_project_status._load_context_with_trusted_git(
                ROOT,
                verify_git=True,
            )

    def test_historical_unledgered_exception_survives_newer_ledger_transition(
        self,
    ) -> None:
        current = render_project_status.load_context(ROOT, verify_git=False)
        context = replace(
            current,
            status=_as_project_status_v2(current.status),
            direct_release=None,
        )
        historical_authority = (
            context.status.published_unledgered_authorities[0]
        )

        def seed(root: Path, *, include_recovery: bool) -> None:
            for relative in (
                historical_authority.record_path,
                historical_authority.erratum_path,
                historical_authority.key_disposition_path,
                "security/release-ledger-roots/v4.4.0.pub.pem",
                "tests/baseline/v4.3.0/RELEASE_LEDGER.json",
            ):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            if include_recovery:
                recovery_ledger = (
                    root / "evidence/release-ledgers/v4.4.1/RELEASE_LEDGER.json"
                )
                recovery_ledger.parent.mkdir(parents=True)
                recovery_ledger.write_text("{}\n", encoding="utf-8")

        transitions = (
            ("release-line", "4.4.1", "4.4.1"),
            ("unreleased-development", "4.4.2.dev0", "4.4.1"),
            ("release-candidate", "4.4.2", "4.4.1"),
            ("release-line", "4.4.2", "4.4.2"),
        )
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            seed(root, include_recovery=True)
            latest_ledger = (
                root / "evidence/release-ledgers/v4.4.2/RELEASE_LEDGER.json"
            )
            latest_ledger.parent.mkdir(parents=True, exist_ok=True)
            latest_ledger.write_text("{}\n", encoding="utf-8")
            for lifecycle, source_version, ledger_version in transitions:
                with self.subTest(
                    lifecycle=lifecycle,
                    source_version=source_version,
                    ledger_version=ledger_version,
                ):
                    status = replace(
                        context.status,
                        lifecycle=lifecycle,
                        ledger_path=(
                            "evidence/release-ledgers/"
                            f"v{ledger_version}/RELEASE_LEDGER.json"
                        ),
                    )
                    ledger = replace(
                        context.ledger,
                        schema_version="evoguard-release-ledger-v2",
                        version=ledger_version,
                        tag=f"v{ledger_version}",
                        release_url=(
                            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/"
                            f"releases/tag/v{ledger_version}"
                        ),
                    )
                    exception = render_project_status._load_published_unledgered(
                        root,
                        status,
                        ledger,
                        source_version,
                        verify_git=False,
                        authority=historical_authority,
                    )
                    self.assertEqual(exception.version, "4.4.0")
                    self.assertEqual(exception.recovery_version, "4.4.1")
                    if source_version.startswith("4.4.2"):
                        summary = render_project_status._release_summary(
                            replace(
                                context,
                                status=status,
                                ledger=ledger,
                                source_version=source_version,
                                published_unledgered=exception,
                            )
                        )
                        self.assertNotIn(
                            "recovery successor to `v4.4.0`",
                            summary,
                        )

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            seed(root, include_recovery=False)
            skipped_ledger = (
                root / "evidence/release-ledgers/v4.4.2/RELEASE_LEDGER.json"
            )
            skipped_ledger.parent.mkdir(parents=True)
            skipped_ledger.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status._load_published_unledgered(
                    root,
                    replace(
                        context.status,
                        lifecycle="release-line",
                        ledger_path=(
                            "evidence/release-ledgers/v4.4.2/RELEASE_LEDGER.json"
                        ),
                    ),
                    replace(
                        context.ledger,
                        schema_version="evoguard-release-ledger-v2",
                        version="4.4.2",
                        tag="v4.4.2",
                    ),
                    "4.4.2",
                    verify_git=False,
                    authority=historical_authority,
                )

    def test_local_key_disposition_accepts_only_bounded_operator_states(self) -> None:
        context = render_project_status.load_context(ROOT, verify_git=False)
        disposition_relative = context.status.published_unledgered_key_disposition_path
        source_disposition = json.loads((ROOT / disposition_relative).read_text(encoding="utf-8"))
        public_key_relative = source_disposition["key"]["public_key_path"]

        def seed(root: Path, disposition: dict[str, object]) -> None:
            for relative in (
                context.status.published_unledgered_record_path,
                context.status.published_unledgered_erratum_path,
                public_key_relative,
                "tests/baseline/v4.3.0/RELEASE_LEDGER.json",
                "evidence/release-ledgers/v4.4.2/RELEASE_LEDGER.json",
            ):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            target = root / disposition_relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(disposition, indent=2) + "\n",
                encoding="utf-8",
            )

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            removed = json.loads(json.dumps(source_disposition))
            removed["disposition"]["status"] = "local-file-removed"
            removed["disposition"]["observed_utc"] = "2026-07-29T08:30:00Z"
            seed(root, removed)
            authority = render_project_status._load_published_unledgered(
                root,
                context.status,
                context.ledger,
                context.source_version,
                verify_git=False,
            )
            self.assertEqual(
                authority.key_disposition_status,
                "local-file-removed",
            )

        invalid_mutations = (
            lambda item: item["disposition"].update(
                {"status": "local-file-removed", "observed_utc": None}
            ),
            lambda item: item["disposition"].update(
                {
                    "status": "pending-operator-removal",
                    "observed_utc": "2026-07-29T03:30:00Z",
                }
            ),
            lambda item: item["disposition"].update(
                {
                    "status": "local-file-removed",
                    "observed_utc": "2026-02-31T00:00:00Z",
                }
            ),
            lambda item: item["disposition"].update(
                {
                    "status": "local-file-removed",
                    "observed_utc": "2026-07-29T02:00:00Z",
                }
            ),
            lambda item: item["key"].__setitem__(
                "private_file_basename",
                r"C:\Users\operator\release-ledger-v4.4.0.private.pem",
            ),
            lambda item: item["non_claims"].__setitem__(
                2,
                "The private key was securely erased.",
            ),
        )
        for mutate in invalid_mutations:
            with self.subTest(mutate=mutate), TemporaryDirectory() as temporary:
                root = Path(temporary)
                invalid = json.loads(json.dumps(source_disposition))
                mutate(invalid)
                seed(root, invalid)
                with self.assertRaises(render_project_status.ProjectStatusError):
                    render_project_status._load_published_unledgered(
                        root,
                        context.status,
                        context.ledger,
                        context.source_version,
                        verify_git=False,
                    )

    def test_workflow_gate_is_structural_not_a_comment_substring(self) -> None:
        spec = render_project_status._WORKFLOW_SPECS[0]
        text = (ROOT / spec.path).read_text(encoding="utf-8")
        needle = f"    if: {spec.gate_expression}"
        self.assertIn(needle, text)
        bypass = text.replace(
            needle,
            f"    if: true # {spec.gate_expression}",
            1,
        )
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._verify_workflow_text(
                bypass,
                spec,
                ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"),
            )

    def test_workflow_contract_rejects_live_extra_job_and_wrong_needs(self) -> None:
        spec = render_project_status._WORKFLOW_SPECS[0]
        text = (ROOT / spec.path).read_text(encoding="utf-8")
        extra_job = (
            text
            + "\n  live-bypass:\n"
            + "    runs-on: ubuntu-latest\n"
            + "    steps:\n"
            + "      - run: echo live\n"
        )
        wrong_needs = text.replace("    needs: metadata", "    needs: []", 1)
        merged_job_fields = text.replace(
            "    runs-on: ubuntu-24.04",
            "    <<: *unreviewed-job-fields\n    runs-on: ubuntu-24.04",
            1,
        )
        self.assertNotEqual(merged_job_fields, text)
        quoted_if = text.replace(
            "  reverify:\n",
            '  reverify:\n    "if": false\n',
            1,
        )
        structural_spec = replace(spec, reviewed_sha256=None)
        for mutated in (extra_job, wrong_needs, merged_job_fields, quoted_if):
            with self.subTest(), self.assertRaises(
                render_project_status.ProjectStatusError
            ):
                render_project_status._verify_workflow_text(
                    mutated,
                    structural_spec,
                    ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"),
                )

    def test_release_workflow_rejects_any_unguarded_job(self) -> None:
        spec = render_project_status._RELEASE_SPEC
        text = (ROOT / spec.path).read_text(encoding="utf-8")
        bypass = text.replace(
            f"    if: {render_project_status._RELEASE_MAIN_GATE}\n",
            "",
            1,
        )
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._verify_workflow_text(
                bypass,
                spec,
                ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"),
            )

    def test_postpublication_verifier_byte_drift_is_rejected(self) -> None:
        source = ROOT / render_project_status._RELEASE_PUBLISHED_VERIFY_PATH
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / render_project_status._RELEASE_PUBLISHED_VERIFY_PATH
            target.parent.mkdir(parents=True)
            target.write_bytes(source.read_bytes() + b"# drift\n")
            with self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "post-publication verifier bytes differ",
            ):
                render_project_status._verify_release_published_workflow(root)

    def test_asset_names_in_comments_do_not_satisfy_active_handling(self) -> None:
        spec = render_project_status._WorkflowSpec(
            "test",
            "test.yml",
            (("gate", ()),),
            "gate",
            render_project_status._ARTIFACT_GATE,
            ("gate",),
        )
        text = (
            "jobs:\n"
            "  gate:\n"
            f"    if: {render_project_status._ARTIFACT_GATE}\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      # evo-guard.pyz evo-guard.spdx.json SHA256SUMS\n"
            "      - run: echo inert\n"
        )
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._verify_workflow_text(
                text,
                spec,
                ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"),
            )

    def test_asset_names_without_reviewed_operations_are_rejected(self) -> None:
        spec = next(
            workflow
            for workflow in render_project_status._WORKFLOW_SPECS
            if workflow.phase == "E"
        )
        text = (ROOT / spec.path).read_text(encoding="utf-8")
        sentinel = render_project_status._ASSET_SENTINELS[("E", "build")][0]
        self.assertIn(sentinel, text)
        bypass = text.replace(
            sentinel,
            "echo bypass",
            1,
        )
        bypass = bypass.replace(
            "      - name: Set up the no-secret builder Python runtime",
            f'      - name: "{sentinel}"',
            1,
        )
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._verify_workflow_text(
                bypass,
                spec,
                ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"),
            )

    def test_every_generated_document_is_byte_exact(self) -> None:
        rendered = render_project_status.build_rendered_files(
            ROOT,
            verify_git=False,
        )
        self.assertEqual(
            {path.relative_to(ROOT).as_posix() for path in rendered},
            set(render_project_status._MARKER_FILES),
        )
        stale = {
            path.relative_to(ROOT).as_posix()
            for path, expected in rendered.items()
            if path.read_bytes() != expected
        }
        self.assertEqual(stale, set())

    def test_source_lifecycle_generated_paths_are_exactly_authorized(self) -> None:
        current = render_project_status.load_context(ROOT, verify_git=False)
        base_context = replace(
            current,
            status=_as_project_status_v2(current.status),
            direct_release=None,
        )
        development_context = replace(
            base_context,
            source_version="4.4.1.dev0",
            status=replace(
                base_context.status,
                lifecycle="unreleased-development",
            ),
        )
        candidate_context = replace(
            base_context,
            source_version="4.4.1",
            status=replace(
                base_context.status,
                lifecycle="release-candidate",
            ),
        )
        published_context = replace(
            base_context,
            source_version="4.4.0",
            status=replace(
                base_context.status,
                lifecycle="published-unledgered",
            ),
        )
        with mock.patch.object(
            render_project_status,
            "load_context",
            return_value=development_context,
        ):
            development_rendered = render_project_status.build_rendered_files(
                ROOT,
                verify_git=False,
            )
        with mock.patch.object(
            render_project_status,
            "load_context",
            return_value=candidate_context,
        ):
            candidate_rendered = render_project_status.build_rendered_files(
                ROOT,
                verify_git=False,
            )
        with mock.patch.object(
            render_project_status,
            "load_context",
            return_value=published_context,
        ):
            published_rendered = render_project_status.build_rendered_files(
                ROOT,
                verify_git=False,
            )

        development_to_candidate = {
            path.relative_to(ROOT).as_posix()
            for path, development_bytes in development_rendered.items()
            if development_bytes != candidate_rendered[path]
        }
        candidate_to_published = {
            path.relative_to(ROOT).as_posix()
            for path, candidate_bytes in candidate_rendered.items()
            if candidate_bytes != published_rendered[path]
        }
        expected = {
            "CHANGELOG.md",
            "README.md",
            "ROADMAP.md",
            "SECURITY.md",
            "docs/GITHUB_ARTIFACT_ATTESTATIONS.md",
            "docs/PROJECT_STATUS.md",
            "docs/RELEASE_STATUS.md",
            "docs/SBOM.md",
            "docs/architecture/REFACTOR_PROGRAM.md",
        }
        self.assertEqual(development_to_candidate, expected)
        self.assertEqual(candidate_to_published, expected)
        self.assertLessEqual(development_to_candidate, set(candidate_scope.ALLOWED_PATHS))
        self.assertLessEqual(candidate_to_published, set(candidate_scope.ALLOWED_PATHS))

    def test_candidate_immutable_docs_do_not_freeze_a_dev0_current_claim(self) -> None:
        immutable_docs = (
            "docs/START_HERE.md",
            "docs/RELEASE_TRUST_PIPELINE.md",
            "docs/RELEASE_LEDGER_V2.md",
            "docs/RECORD_VERIFICATION.md",
            "docs/OPERATIONAL_TELEMETRY.md",
            "docs/OPERATING_PROFILES.md",
            "docs/BLACKBOX.md",
            "docs/INDEPENDENT_EVALUATION.md",
        )
        for relative in immutable_docs:
            with self.subTest(path=relative):
                self.assertNotIn(relative, candidate_scope.ALLOWED_PATHS)
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertNotIn("current `4.4.1.dev0`", text)
                self.assertNotIn(
                    "active source identity is `4.4.1.dev0`",
                    text,
                )
                self.assertNotIn("current source is `4.4.1.dev0`", text)

    def test_markers_are_unique_and_outside_metadata_and_fences(self) -> None:
        rendered = render_project_status.build_rendered_files(
            ROOT,
            verify_git=False,
        )
        for path, content in rendered.items():
            text = content.decode("utf-8")
            locations = render_project_status._marker_locations(text)
            expected = set(render_project_status._MARKER_FILES[path.relative_to(ROOT).as_posix()])
            self.assertEqual(set(locations), expected)

    def test_marker_parser_rejects_ambiguous_placement(self) -> None:
        token = "TEST"
        begin = f"<!-- BEGIN EVOGUARD_PROJECT_STATUS:{token} -->"
        end = f"<!-- END EVOGUARD_PROJECT_STATUS:{token} -->"
        invalid = (
            f"---\n{begin}\n---\n{end}\n",
            f"```\n{begin}\n{end}\n```\n",
            f"{begin}\n{begin}\n{end}\n",
            f"{begin}\n",
            (
                f"{begin}\n"
                "<!-- BEGIN EVOGUARD_PROJECT_STATUS:INNER -->\n"
                "<!-- END EVOGUARD_PROJECT_STATUS:INNER -->\n"
                f"{end}\n"
            ),
        )
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(
                render_project_status.ProjectStatusError
            ):
                render_project_status._marker_locations(text)

    def test_marker_parser_rejects_hidden_and_non_standalone_markers(self) -> None:
        begin = "<!-- BEGIN EVOGUARD_PROJECT_STATUS:TEST -->"
        end = "<!-- END EVOGUARD_PROJECT_STATUS:TEST -->"
        invalid = (
            f"prefix {begin}\n{end}\n",
            f"{begin} trailing\n{end}\n",
            f"    {begin}\n    {end}\n",
            f"<div hidden>\n{begin}\n{end}\n</div>\n",
            f"<details open>\n{begin}\n{end}\n</details>\n",
            f"<!-- hidden block\n{begin}\n{end}\n-->\n",
            f"visible prefix <!-- hidden span\n{begin}\n{end}\n-->\n",
            f"visible prefix <div hidden>\n{begin}\n{end}\n</div>\n",
            f"<section style=\"display:none\">\n{begin}\n{end}\n</section>\n",
            f"<table>\n{begin}\n{end}\n</table>\n",
            f"<details\nhidden>\n{begin}\n{end}\n</details>\n",
            f"\\`<details>\\`\n{begin}\n{end}\n\\`</details>\\`\n",
        )
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(
                render_project_status.ProjectStatusError
            ):
                render_project_status._marker_locations(text)

    def test_marker_parser_tracks_commonmark_fence_lengths_and_indentation(self) -> None:
        begin = "<!-- BEGIN EVOGUARD_PROJECT_STATUS:TEST -->"
        end = "<!-- END EVOGUARD_PROJECT_STATUS:TEST -->"
        hidden = (
            f"```` python\n{begin}\n{end}\n````\n",
            f"~~~~ shell info\n{begin}\n{end}\n~~~~\n",
            f"   ```python\n{begin}\n{end}\n   ```\n",
            f"````\n```\n{begin}\n{end}\n````\n",
        )
        for text in hidden:
            with self.subTest(text=text), self.assertRaises(
                render_project_status.ProjectStatusError
            ):
                render_project_status._marker_locations(text)

        visible = (
            f"```python\ncode\n````\n{begin}\nbody\n{end}\n",
            f"~~~~ shell\ncode\n~~~~~\n{begin}\nbody\n{end}\n",
            f"    ````\n{begin}\nbody\n{end}\n",
            f"``` bad`info\n{begin}\nbody\n{end}\n",
            f"`<repo>` and ``<table>`` placeholders\n{begin}\nbody\n{end}\n",
        )
        for text in visible:
            with self.subTest(text=text):
                self.assertEqual(
                    set(render_project_status._marker_locations(text)),
                    {"TEST"},
                )

    def test_ledger_directory_version_and_identity_fields_are_bound(self) -> None:
        base_context = render_project_status.load_context(ROOT, verify_git=False)
        source_ledger = json.loads(
            (
                ROOT / "tests/baseline/v4.3.0/RELEASE_LEDGER.json"
            ).read_text(encoding="utf-8")
        )
        cases = (
            ("v4.3.1", lambda ledger: None),
            (
                "v4.3.0",
                lambda ledger: ledger.__setitem__("schema_version", "wrong"),
            ),
            (
                "v4.3.0",
                lambda ledger: ledger["project"].__setitem__("name", "wrong"),
            ),
            (
                "v4.3.0",
                lambda ledger: ledger["release"].__setitem__("repository", "wrong/repo"),
            ),
        )
        for directory, mutate in cases:
            with self.subTest(directory=directory), TemporaryDirectory() as temporary:
                root = Path(temporary)
                ledger = json.loads(json.dumps(source_ledger))
                mutate(ledger)
                ledger_path = (
                    root / "tests" / "baseline" / directory / "RELEASE_LEDGER.json"
                )
                ledger_path.parent.mkdir(parents=True)
                ledger_path.write_text(
                    json.dumps(ledger, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                status = replace(
                    base_context.status,
                    ledger_path=ledger_path.relative_to(root).as_posix(),
                )
                with self.assertRaises(render_project_status.ProjectStatusError):
                    render_project_status._load_ledger(
                        root,
                        status,
                        verify_git=False,
                    )

    def test_every_discovered_historical_v1_ledger_is_validated(self) -> None:
        base_context = render_project_status.load_context(ROOT, verify_git=False)
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "tests" / "baseline"
            for version in ("4.2.0", "4.3.0"):
                target = baseline / f"v{version}" / "RELEASE_LEDGER.json"
                target.parent.mkdir(parents=True)
                target.write_bytes(
                    (
                        ROOT
                        / f"tests/baseline/v{version}/RELEASE_LEDGER.json"
                    ).read_bytes()
                )
            historical = baseline / "v4.2.0" / "RELEASE_LEDGER.json"
            malformed = json.loads(historical.read_text(encoding="utf-8"))
            malformed["project"]["name"] = "not EvoOM Guard"
            historical.write_text(json.dumps(malformed) + "\n", encoding="utf-8")
            status = replace(
                base_context.status,
                ledger_path="tests/baseline/v4.3.0/RELEASE_LEDGER.json",
            )
            with self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "project identity",
            ):
                render_project_status._load_ledger(
                    root,
                    status,
                    verify_git=False,
                )

    def test_every_discovered_historical_v2_ledger_is_validated(self) -> None:
        base_context = render_project_status.load_context(ROOT, verify_git=False)
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger_root = root / "evidence" / "release-ledgers"
            for version in ("4.4.0", "4.5.0"):
                target = ledger_root / f"v{version}" / "RELEASE_LEDGER.json"
                target.parent.mkdir(parents=True)
                target.write_text(
                    json.dumps(_minimal_v2_ledger(version)) + "\n",
                    encoding="utf-8",
                )
            historical = ledger_root / "v4.4.0" / "RELEASE_LEDGER.json"
            malformed = json.loads(historical.read_text(encoding="utf-8"))
            malformed["project"]["name"] = "not EvoOM Guard"
            historical.write_text(json.dumps(malformed) + "\n", encoding="utf-8")
            status = replace(
                base_context.status,
                ledger_path=(
                    "evidence/release-ledgers/v4.5.0/RELEASE_LEDGER.json"
                ),
            )
            with (
                mock.patch.object(render_project_status, "_validate_v2_ledger"),
                self.assertRaisesRegex(
                    render_project_status.ProjectStatusError,
                    "project identity",
                ),
            ):
                render_project_status._load_ledger(
                    root,
                    status,
                    verify_git=False,
                )

    def test_v2_ledger_set_cannot_roll_back_across_head_ancestry(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for version in ("4.0.2", "4.1.0", "4.2.0", "4.3.0"):
                v1 = root / f"tests/baseline/v{version}/RELEASE_LEDGER.json"
                v1.parent.mkdir(parents=True)
                v1.write_bytes(
                    (
                        ROOT
                        / f"tests/baseline/v{version}/RELEASE_LEDGER.json"
                    ).read_bytes()
                )
            v2 = root / "evidence/release-ledgers/v4.4.0/RELEASE_LEDGER.json"
            v2.parent.mkdir(parents=True)
            v2.write_text(
                json.dumps(_minimal_v2_ledger()) + "\n",
                encoding="utf-8",
            )
            status_document = _project_status_v2_fixture()
            status_document["published_release"]["ledger"] = (
                "evidence/release-ledgers/v4.4.0/RELEASE_LEDGER.json"
            )
            status_path = root / "PROJECT_STATUS.json"
            status_path.write_text(
                json.dumps(status_document) + "\n",
                encoding="utf-8",
            )
            commands = (
                ("init", "-q", "--initial-branch=main"),
                ("config", "user.name", "Status Test"),
                ("config", "user.email", "status@example.invalid"),
                ("config", "core.autocrlf", "false"),
                ("add", "."),
                ("commit", "-qm", "record v4.4.0"),
            )
            for command in commands:
                subprocess.run(
                    ["git", *command],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )
            v2.unlink()
            v2.parent.rmdir()
            status_document["published_release"]["ledger"] = (
                "tests/baseline/v4.3.0/RELEASE_LEDGER.json"
            )
            status_path.write_text(
                json.dumps(status_document) + "\n",
                encoding="utf-8",
            )
            for command in (
                ("add", "-A"),
                ("commit", "-qm", "attempt release rollback"),
            ):
                subprocess.run(
                    ["git", *command],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )

            with self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "non-append change",
            ):
                render_project_status._load_ledger(
                    root,
                    render_project_status.load_status(root),
                    verify_git=True,
                )

    def test_v2_append_only_proof_covers_side_branch_merge_history(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = root / "evidence/release-ledgers/v4.4.0/RELEASE_LEDGER.json"
            (root / ".gitkeep").write_text("", encoding="utf-8")
            for command in (
                ("init", "-q", "--initial-branch=main"),
                ("config", "user.name", "Status Test"),
                ("config", "user.email", "status@example.invalid"),
                ("config", "core.autocrlf", "false"),
                ("add", "."),
                ("commit", "-qm", "initial"),
                ("branch", "side"),
                ("checkout", "-q", "side"),
            ):
                subprocess.run(
                    ["git", *command],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )
            ledger.parent.mkdir(parents=True)
            ledger.write_text('{"branch":"side"}\n', encoding="utf-8")
            subprocess.run(
                ["git", "add", "."],
                cwd=root,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "side ledger"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "checkout", "-q", "main"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            ledger.parent.mkdir(parents=True, exist_ok=True)
            ledger.write_text('{"branch":"main"}\n', encoding="utf-8")
            subprocess.run(
                ["git", "add", "."],
                cwd=root,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "main ledger"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            merge = subprocess.run(
                ["git", "merge", "--no-ff", "--no-commit", "side"],
                cwd=root,
                check=False,
                capture_output=True,
            )
            self.assertNotEqual(merge.returncode, 0)
            ledger.write_text('{"branch":"main"}\n', encoding="utf-8")
            subprocess.run(
                ["git", "add", "."],
                cwd=root,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "resolve merge"],
                cwd=root,
                check=True,
                capture_output=True,
            )

            with self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "non-append change",
            ):
                render_project_status._verify_append_only_v2_history(
                    root,
                    [((4, 4, 0), ledger)],
                )

    def test_frozen_v1_ledger_set_rejects_historical_deletion(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for version in ("4.0.2", "4.1.0", "4.2.0", "4.3.0"):
                ledger = root / f"tests/baseline/v{version}/RELEASE_LEDGER.json"
                ledger.parent.mkdir(parents=True)
                ledger.write_bytes(
                    (
                        ROOT
                        / f"tests/baseline/v{version}/RELEASE_LEDGER.json"
                    ).read_bytes()
                )
            (root / "tests/baseline/v4.1.0/RELEASE_LEDGER.json").unlink()
            discovered = render_project_status._discover_ledgers(
                root,
                root / "tests/baseline",
            )
            with self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "frozen v1 ledger set differs",
            ):
                render_project_status._verify_frozen_v1_set(root, discovered)

    def test_append_only_proof_rejects_shallow_git_history(self) -> None:
        with (
            mock.patch.object(
                render_project_status,
                "_git",
                return_value="true",
            ),
            self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "non-shallow Git history",
            ),
        ):
            render_project_status._verify_append_only_v2_history(ROOT, ())

    def test_new_v1_ledger_after_v430_is_rejected(self) -> None:
        base_context = render_project_status.load_context(ROOT, verify_git=False)
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger_path = (
                root
                / "tests"
                / "baseline"
                / "v4.4.0"
                / "RELEASE_LEDGER.json"
            )
            ledger_path.parent.mkdir(parents=True)
            ledger = json.loads(
                (
                    ROOT / "tests/baseline/v4.3.0/RELEASE_LEDGER.json"
                ).read_text(encoding="utf-8")
            )
            ledger["project"]["version"] = "4.4.0"
            ledger["release"]["tag"] = "v4.4.0"
            ledger_path.write_text(json.dumps(ledger) + "\n", encoding="utf-8")
            status = replace(
                base_context.status,
                ledger_path=ledger_path.relative_to(root).as_posix(),
            )
            with self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "v1 is frozen",
            ):
                render_project_status._load_ledger(
                    root,
                    status,
                    verify_git=False,
                )

    def test_v2_no_git_mode_skips_external_boundary_and_derives_evidence(self) -> None:
        base_context = render_project_status.load_context(ROOT, verify_git=False)
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger_path = (
                root
                / "evidence"
                / "release-ledgers"
                / "v4.4.0"
                / "RELEASE_LEDGER.json"
            )
            ledger_path.parent.mkdir(parents=True)
            ledger_path.write_text(
                json.dumps(_minimal_v2_ledger(), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            status = replace(
                base_context.status,
                ledger_path=ledger_path.relative_to(root).as_posix(),
            )
            with mock.patch.object(
                render_project_status,
                "_validate_v2_ledger",
            ) as validator:
                ledger = render_project_status._load_ledger(
                    root,
                    status,
                    verify_git=False,
                )
            validator.assert_not_called()
            self.assertEqual(
                ledger.schema_version,
                "evoguard-release-ledger-v2",
            )
            self.assertEqual(ledger.artifacts, render_project_status._PIPELINE_ASSETS)
            self.assertTrue(ledger.sbom_recorded)
            self.assertTrue(ledger.pipeline_operational_evidence_recorded)
            self.assertTrue(ledger.pipeline_publication_evidence_recorded)

    def test_v2_validation_failure_and_validation_race_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger_path = (
                root
                / "evidence"
                / "release-ledgers"
                / "v4.4.0"
                / "RELEASE_LEDGER.json"
            )
            ledger_path.parent.mkdir(parents=True)
            original = json.dumps(_minimal_v2_ledger(), sort_keys=True) + "\n"
            ledger_path.write_text(original, encoding="utf-8")
            with (
                mock.patch.object(
                    render_project_status,
                    "_verify_tracked_bytes",
                ),
                mock.patch.object(
                    render_project_status,
                    "_verify_clean_directory",
                ),
                mock.patch.object(
                    render_project_status,
                    "_validate_v2_ledger",
                    side_effect=render_project_status.ProjectStatusError(
                        "validator rejected"
                    ),
                ),
                self.assertRaises(render_project_status.ProjectStatusError),
            ):
                render_project_status._load_one_ledger(
                    root,
                    ledger_path,
                    verify_git=True,
                )

            def mutate(*_arguments: object) -> None:
                ledger_path.write_text(
                    original.replace('"immutable": true', '"immutable": false'),
                    encoding="utf-8",
                )

            with (
                mock.patch.object(
                    render_project_status,
                    "_verify_tracked_bytes",
                ),
                mock.patch.object(
                    render_project_status,
                    "_verify_clean_directory",
                ),
                mock.patch.object(
                    render_project_status,
                    "_validate_v2_ledger",
                    side_effect=mutate,
                ),
                self.assertRaisesRegex(
                    render_project_status.ProjectStatusError,
                    "changed during external validation",
                ),
            ):
                render_project_status._load_one_ledger(
                    root,
                    ledger_path,
                    verify_git=True,
                )

    def test_v2_validator_is_extracted_from_tag_parent_not_candidate(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            validator = root / "tools/ci/validate_release_ledger_v2.py"
            trusted_key = (
                root / "security/release-ledger-roots/v4.4.0.pub.pem"
            )
            ledger_directory = root / "evidence/release-ledgers/v4.4.0"
            validator.parent.mkdir(parents=True)
            trusted_key.parent.mkdir(parents=True)
            ledger_directory.mkdir(parents=True)
            parent_marker = root / "parent-validator-ran"
            evil_marker = root / "candidate-validator-ran"
            validator.write_text(
                "import os\nfrom pathlib import Path\n"
                "Path(os.environ['EVOGUARD_PARENT_MARKER']).write_text("
                "'parent', encoding='utf-8')\n",
                encoding="utf-8",
            )
            trusted_key.write_text("PUBLIC KEY\n", encoding="utf-8")
            for relative in (
                "tests/baseline/schema/release-ledger-v2.schema.json",
                "tools/ci/collect_repository_controls_v2.py",
                "ops/build_pyz.py",
                "ops/generate_spdx_sbom.py",
                "tools/ci/verify_spdx_attestation.py",
            ):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(f"# {relative}\n", encoding="utf-8")
            for command in (
                ("init", "-q"),
                ("config", "user.name", "Status Test"),
                ("config", "user.email", "status@example.invalid"),
                ("config", "core.autocrlf", "false"),
                ("add", "."),
                ("commit", "-qm", "trusted parent"),
            ):
                subprocess.run(
                    ["git", *command],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )
            parent = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                text=True,
            ).strip()
            parent_tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"],
                cwd=root,
                text=True,
            ).strip()
            (root / "release.txt").write_text("release\n", encoding="utf-8")
            for command in (
                ("add", "release.txt"),
                ("commit", "-qm", "release"),
                ("tag", "v4.4.0"),
            ):
                subprocess.run(
                    ["git", *command],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )
            release_commit = subprocess.check_output(
                ["git", "rev-parse", "v4.4.0^{commit}"],
                cwd=root,
                text=True,
            ).strip()
            ledger = {
                "schema_version": "evoguard-release-ledger-v2",
                "source": {
                    "parent_commit_sha": parent,
                    "parent_tree_sha": parent_tree,
                },
                "release": {"commit_sha": release_commit},
            }
            ledger_path = ledger_directory / "RELEASE_LEDGER.json"
            ledger_path.write_text(json.dumps(ledger) + "\n", encoding="utf-8")
            validator.write_text(
                "import os\nfrom pathlib import Path\n"
                "Path(os.environ['EVOGUARD_EVIL_MARKER']).write_text("
                "'candidate', encoding='utf-8')\n",
                encoding="utf-8",
            )

            with mock.patch.dict(
                os.environ,
                {
                    "EVOGUARD_PARENT_MARKER": str(parent_marker),
                    "EVOGUARD_EVIL_MARKER": str(evil_marker),
                },
            ):
                render_project_status._validate_v2_ledger(
                    root,
                    ledger_directory,
                    "4.4.0",
                )
            self.assertTrue(parent_marker.exists())
            self.assertFalse(evil_marker.exists())

            parent_marker.unlink()
            ledger["source"]["parent_commit_sha"] = "f" * 40
            ledger_path.write_text(json.dumps(ledger) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "tag-derived ancestry",
            ):
                render_project_status._validate_v2_ledger(
                    root,
                    ledger_directory,
                    "4.4.0",
                )
            self.assertFalse(parent_marker.exists())

    def test_ledger_rejects_a_symlinked_version_directory(self) -> None:
        base_context = render_project_status.load_context(ROOT, verify_git=False)
        with TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "root"
            external = parent / "external" / "v4.3.0"
            baseline = root / "tests" / "baseline"
            external.mkdir(parents=True)
            baseline.mkdir(parents=True)
            (external / "RELEASE_LEDGER.json").write_bytes(
                (ROOT / "tests/baseline/v4.3.0/RELEASE_LEDGER.json").read_bytes()
            )
            try:
                os.symlink(
                    external,
                    baseline / "v4.3.0",
                    target_is_directory=True,
                )
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            original_scandir = os.scandir
            enumerated: list[Path] = []

            def no_external_enumeration(path: object) -> object:
                absolute = Path(path).absolute()  # type: ignore[arg-type]
                enumerated.append(absolute)
                if absolute == external.absolute():
                    self.fail("ledger discovery descended into an external symlink")
                return original_scandir(path)  # type: ignore[arg-type]

            with (
                mock.patch.object(
                    render_project_status.os,
                    "scandir",
                    side_effect=no_external_enumeration,
                ),
                self.assertRaises(render_project_status.ProjectStatusError),
            ):
                render_project_status._load_ledger(
                    root,
                    base_context.status,
                    verify_git=False,
                )
            self.assertNotIn(external.absolute(), enumerated)

    def test_ledger_reparse_directory_is_rejected_before_descent(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "tests" / "baseline"
            version_directory = baseline / "v4.3.0"
            version_directory.mkdir(parents=True)
            metadata = os.lstat(version_directory)
            identity = (metadata.st_dev, metadata.st_ino)
            original_reparse = render_project_status._is_reparse_point
            original_scandir = os.scandir
            enumerated: list[Path] = []

            def mark_version_as_reparse(candidate: os.stat_result) -> bool:
                if (candidate.st_dev, candidate.st_ino) == identity:
                    return True
                return original_reparse(candidate)

            def reject_version_descent(path: object) -> object:
                absolute = Path(path).absolute()  # type: ignore[arg-type]
                enumerated.append(absolute)
                if absolute == version_directory.absolute():
                    self.fail("ledger discovery descended into a reparse directory")
                return original_scandir(path)  # type: ignore[arg-type]

            with (
                mock.patch.object(
                    render_project_status,
                    "_is_reparse_point",
                    side_effect=mark_version_as_reparse,
                ),
                mock.patch.object(
                    render_project_status.os,
                    "scandir",
                    side_effect=reject_version_descent,
                ),
                self.assertRaises(render_project_status.ProjectStatusError),
            ):
                render_project_status._discover_ledgers(root, baseline)
            self.assertEqual(enumerated, [baseline.absolute()])


    def test_ledger_rejects_an_out_of_root_configured_path(self) -> None:
        base_context = render_project_status.load_context(ROOT, verify_git=False)
        with TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "root"
            inside = root / "tests" / "baseline" / "v4.3.0"
            outside = parent / "outside"
            inside.mkdir(parents=True)
            outside.mkdir()
            ledger_bytes = (
                ROOT / "tests/baseline/v4.3.0/RELEASE_LEDGER.json"
            ).read_bytes()
            (inside / "RELEASE_LEDGER.json").write_bytes(ledger_bytes)
            (outside / "RELEASE_LEDGER.json").write_bytes(ledger_bytes)
            status = replace(
                base_context.status,
                ledger_path="../outside/RELEASE_LEDGER.json",
            )
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status._load_ledger(
                    root,
                    status,
                    verify_git=False,
                )

    def test_git_binding_rejects_dirty_and_untracked_frozen_material(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = "tests/baseline/v1.0.0/RELEASE_LEDGER.json"
            path = root / relative
            path.parent.mkdir(parents=True)
            original = b'{"ledger":true}\n'
            path.write_bytes(original)
            (root / ".gitignore").write_text("*.ignored\n", encoding="utf-8")
            commands = (
                ("init", "-q"),
                ("config", "user.name", "Status Test"),
                ("config", "user.email", "status@example.invalid"),
                ("config", "core.autocrlf", "false"),
                ("add", "."),
                ("commit", "-qm", "fixture"),
            )
            for command in commands:
                subprocess.run(
                    ["git", *command],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )
            render_project_status._verify_tracked_bytes(root, relative, original)
            path.write_bytes(b'{"ledger":false}\n')
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status._verify_tracked_bytes(
                    root,
                    relative,
                    path.read_bytes(),
                )
            path.write_bytes(original)
            (path.parent / "UNTRACKED").write_text("unexpected", encoding="utf-8")
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status._verify_tracked_bytes(root, relative, original)
            (path.parent / "UNTRACKED").unlink()
            (path.parent / "HIDDEN.ignored").write_text(
                "unexpected",
                encoding="utf-8",
            )
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status._verify_tracked_bytes(root, relative, original)

    def test_git_resolver_ignores_relative_candidate_and_detects_swap(self) -> None:
        host = render_project_status._resolve_git(ROOT)
        with TemporaryDirectory() as temporary:
            candidate = Path(temporary)
            fake = candidate / ("git.exe" if os.name == "nt" else "git")
            fake.write_bytes(b"candidate-controlled Git")
            if os.name != "nt":
                fake.chmod(0o755)
            with (
                mock.patch.object(
                    render_project_status.Path,
                    "cwd",
                    return_value=candidate,
                ),
                mock.patch.dict(
                    os.environ,
                    {"PATH": f".{os.pathsep}{host.path.parent}"},
                ),
            ):
                resolved = render_project_status._resolve_git(candidate)
            self.assertEqual(resolved.path, host.path)

            copied = candidate / (
                "trusted-git.exe" if os.name == "nt" else "trusted-git"
            )
            copied.write_bytes(host.data)
            if os.name != "nt":
                copied.chmod(0o755)
            data, identity = render_project_status._read_host_executable(copied)
            frozen = render_project_status._TrustedGit(
                path=copied,
                data=data,
                identity=identity,
                parent_chain=render_project_status._host_directory_chain(
                    copied.parent
                ),
                search_path=str(copied.parent),
            )
            copied.write_bytes(bytes([data[0] ^ 1]) + data[1:])
            with self.assertRaisesRegex(
                render_project_status.ProjectStatusError,
                "changed",
            ):
                render_project_status._require_git_unchanged(frozen)

    @unittest.skipUnless(os.name == "nt", "Git for Windows characterization")
    def test_git_for_windows_hardlinked_executable_is_accepted(self) -> None:
        trusted = render_project_status._resolve_git(ROOT)
        if trusted.path.stat().st_nlink < 2:
            self.skipTest("host Git executable is not hard-linked")
        data, identity = render_project_status._read_host_executable(trusted.path)
        self.assertEqual(data, trusted.data)
        self.assertEqual(identity, trusted.identity)

    def test_paths_reject_escape_symlink_and_reparse_components(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            outside_file = outside / "status.md"
            outside_file.write_text("outside\n", encoding="utf-8")
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status._safe_path(
                    root,
                    outside_file,
                    leaf="file",
                )

            link = root / "linked"
            try:
                os.symlink(outside, link, target_is_directory=True)
            except OSError:
                pass
            else:
                with self.assertRaises(render_project_status.ProjectStatusError):
                    render_project_status._read_text(root, link / "status.md")
                with self.assertRaises(render_project_status.ProjectStatusError):
                    render_project_status._write_transaction(
                        root,
                        {link / "status.md": b"changed\n"},
                    )
                self.assertEqual(outside_file.read_text(encoding="utf-8"), "outside\n")

            regular = root / "regular.md"
            regular.write_text("regular\n", encoding="utf-8")
            with (
                mock.patch.object(
                    render_project_status,
                    "_is_reparse_point",
                    return_value=True,
                ),
                self.assertRaises(render_project_status.ProjectStatusError),
            ):
                render_project_status._safe_path(root, regular, leaf="file")
            with (
                mock.patch.object(
                    render_project_status,
                    "_is_reparse_point",
                    return_value=True,
                ),
                self.assertRaises(render_project_status.ProjectStatusError),
            ):
                render_project_status._write_transaction(
                    root,
                    {regular: b"changed\n"},
                )
            self.assertEqual(regular.read_text(encoding="utf-8"), "regular\n")

    def test_replace_rechecks_containment(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            source = root / "source.tmp"
            target = outside / "target.md"
            source.write_text("new\n", encoding="utf-8")
            target.write_text("old\n", encoding="utf-8")
            with self.assertRaises(render_project_status.ProjectStatusError):
                render_project_status._replace_path(root, source, target)

    def test_multi_file_writer_is_idempotent(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = tuple(root / f"{index}.md" for index in range(3))
            for path in paths:
                path.write_bytes(b"old\n")
            rendered = {path: f"new-{index}\n".encode() for index, path in enumerate(paths)}
            render_project_status._write_transaction(root, rendered)
            render_project_status._write_transaction(root, rendered)
            for path, expected in rendered.items():
                self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_multi_file_writer_stages_every_file_before_first_replace(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = tuple(root / f"{index}.md" for index in range(3))
            rendered = {
                path: f"new-{index}\n".encode()
                for index, path in enumerate(paths)
            }
            for path in paths:
                path.write_bytes(b"old\n")
            first = True

            def verify_stage(source: Path, target: Path) -> None:
                nonlocal first
                if first:
                    first = False
                    self.assertEqual(len(list(root.rglob("*.tmp"))), 3)
                render_project_status._replace_path(root, source, target)

            render_project_status._write_transaction(
                root,
                rendered,
                replace=verify_stage,
            )
            self.assertFalse(first)

    def test_replace_failure_at_every_position_is_fail_stop(self) -> None:
        for failure_position in range(1, 4):
            with self.subTest(failure_position=failure_position), TemporaryDirectory() as directory:
                root = Path(directory)
                paths = tuple(root / f"{index}.md" for index in range(3))
                originals = {
                    path: f"old-{index}\n".encode()
                    for index, path in enumerate(paths)
                }
                rendered = {
                    path: f"new-{index}\n".encode()
                    for index, path in enumerate(paths)
                }
                for path, content in originals.items():
                    path.write_bytes(content)
                calls = 0
                failed = False

                def fail_once(
                    source: Path,
                    target: Path,
                    *,
                    fail_at: int = failure_position,
                    transaction_root: Path = root,
                ) -> None:
                    nonlocal calls, failed
                    calls += 1
                    if not failed and calls == fail_at:
                        failed = True
                        raise OSError("injected replace failure")
                    render_project_status._replace_path(
                        transaction_root,
                        source,
                        target,
                    )

                with self.assertRaises(
                    render_project_status.ProjectStatusError
                ) as caught:
                    render_project_status._write_transaction(
                        root,
                        rendered,
                        replace=fail_once,
                    )
                self.assertTrue(failed)
                self.assertIn("no automatic rollback was attempted", str(caught.exception))
                for index, path in enumerate(paths):
                    expected = (
                        rendered[path]
                        if index < failure_position - 1
                        else originals[path]
                    )
                    self.assertEqual(path.read_bytes(), expected)
                self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_fail_stop_never_rolls_back_a_late_external_update(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.md"
            second = root / "second.md"
            first.write_bytes(b"old-first\n")
            second.write_bytes(b"old-second\n")
            rendered = {
                first: b"new-first\n",
                second: b"new-second\n",
            }
            calls = 0

            def fail_after_external_update(source: Path, target: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    first.write_bytes(b"external-concurrent-update\n")
                    raise OSError("injected failure after concurrent update")
                render_project_status._replace_path(root, source, target)

            with self.assertRaises(
                render_project_status.ProjectStatusError
            ) as caught:
                render_project_status._write_transaction(
                    root,
                    rendered,
                    replace=fail_after_external_update,
                )
            self.assertIn("no automatic rollback was attempted", str(caught.exception))
            self.assertEqual(first.read_bytes(), b"external-concurrent-update\n")
            self.assertEqual(second.read_bytes(), b"old-second\n")
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_second_cooperating_writer_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "status.md"
            target.write_bytes(b"old\n")
            with (
                render_project_status._exclusive_renderer_lock(root),
                self.assertRaises(
                    render_project_status.ProjectStatusError
                ) as caught,
            ):
                render_project_status._write_transaction(
                    root,
                    {target: b"new\n"},
                )
            self.assertIn("exclusive renderer lock", str(caught.exception))
            self.assertEqual(target.read_bytes(), b"old\n")

    def test_preexisting_lock_fails_closed_without_mutating_it(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            lock_path = render_project_status._renderer_lock_path(root)
            sentinel = b"preexisting-lock\n"
            lock_path.write_bytes(sentinel)
            try:
                with self.assertRaises(
                    render_project_status.ProjectStatusError
                ) as caught:
                    with render_project_status._exclusive_renderer_lock(root):
                        self.fail("preexisting lock must not be acquired")
                self.assertIn("stale lock requires manual inspection", str(caught.exception))
                self.assertEqual(lock_path.read_bytes(), sentinel)
            finally:
                lock_path.unlink(missing_ok=True)

    def test_preexisting_lock_symlink_never_writes_its_target(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "empty-target"
            target.write_bytes(b"")
            lock_path = render_project_status._renderer_lock_path(root)
            try:
                os.symlink(target, lock_path)
            except OSError:
                return
            try:
                with self.assertRaises(render_project_status.ProjectStatusError):
                    with render_project_status._exclusive_renderer_lock(root):
                        self.fail("symlink lock must not be acquired")
                self.assertEqual(target.read_bytes(), b"")
                self.assertTrue(lock_path.is_symlink())
            finally:
                lock_path.unlink(missing_ok=True)

    def test_control_baseexception_at_every_replace_is_fail_stop(self) -> None:
        for error_type in (KeyboardInterrupt, SystemExit):
            for interrupt_after_replace in (False, True):
                for failure_position in range(1, 4):
                    self._assert_replace_interrupt_restores(
                        error_type,
                        failure_position,
                        interrupt_after_replace=interrupt_after_replace,
                    )

    def _assert_replace_interrupt_restores(
        self,
        error_type: type[BaseException],
        failure_position: int,
        *,
        interrupt_after_replace: bool,
    ) -> None:
        with (
            self.subTest(
                error_type=error_type.__name__,
                failure_position=failure_position,
                interrupt_after_replace=interrupt_after_replace,
            ),
            TemporaryDirectory() as directory,
        ):
            root = Path(directory)
            paths = tuple(root / f"{index}.md" for index in range(3))
            originals = {
                path: f"old-{index}\n".encode()
                for index, path in enumerate(paths)
            }
            rendered = {
                path: f"new-{index}\n".encode()
                for index, path in enumerate(paths)
            }
            for path, content in originals.items():
                path.write_bytes(content)
            injected = error_type()
            calls = 0
            failed = False

            def interrupt_once(
                source: Path,
                target: Path,
                *,
                fail_at: int = failure_position,
                transaction_root: Path = root,
            ) -> None:
                nonlocal calls, failed
                calls += 1
                should_interrupt = not failed and calls == fail_at
                if should_interrupt and not interrupt_after_replace:
                    failed = True
                    raise injected
                render_project_status._replace_path(
                    transaction_root,
                    source,
                    target,
                )
                if should_interrupt:
                    failed = True
                    raise injected

            with self.assertRaises(BaseException) as caught:
                render_project_status._write_transaction(
                    root,
                    rendered,
                    replace=interrupt_once,
                )
            self.assertIs(caught.exception, injected)
            committed_count = (
                failure_position if interrupt_after_replace else failure_position - 1
            )
            for index, path in enumerate(paths):
                expected = (
                    rendered[path]
                    if index < committed_count
                    else originals[path]
                )
                self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_control_baseexception_at_every_staging_point_cleans_and_preserves(self) -> None:
        for failure_position in range(1, 4):
            with (
                self.subTest(failure_position=failure_position),
                TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                paths = tuple(root / f"{index}.md" for index in range(3))
                originals = {
                    path: f"old-{index}\n".encode()
                    for index, path in enumerate(paths)
                }
                rendered = {
                    path: f"new-{index}\n".encode()
                    for index, path in enumerate(paths)
                }
                for path, content in originals.items():
                    path.write_bytes(content)
                injected = KeyboardInterrupt()
                original_stage = render_project_status._stage_bytes
                calls = 0

                def interrupt_after_stage(
                    *args: object,
                    stage: object = original_stage,
                    fail_at: int = failure_position,
                    interruption: BaseException = injected,
                    **kwargs: object,
                ) -> Path:
                    nonlocal calls
                    staged = stage(*args, **kwargs)  # type: ignore[operator]
                    calls += 1
                    if calls == fail_at:
                        raise interruption
                    return staged

                with (
                    mock.patch.object(
                        render_project_status,
                        "_stage_bytes",
                        side_effect=interrupt_after_stage,
                    ),
                    self.assertRaises(BaseException) as caught,
                ):
                    render_project_status._write_transaction(root, rendered)
                self.assertIs(caught.exception, injected)
                for path, expected in originals.items():
                    self.assertEqual(path.read_bytes(), expected)
                self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_commit_baseexception_does_not_trigger_rollback_replacements(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = tuple(root / f"{index}.md" for index in range(3))
            rendered = {
                path: f"new-{index}\n".encode()
                for index, path in enumerate(paths)
            }
            for path in paths:
                path.write_bytes(b"old\n")
            commit_interrupt = KeyboardInterrupt()
            calls = 0

            def interrupt_second_commit(source: Path, target: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise commit_interrupt
                render_project_status._replace_path(root, source, target)

            with self.assertRaises(BaseException) as caught:
                render_project_status._write_transaction(
                    root,
                    rendered,
                    replace=interrupt_second_commit,
                )
            self.assertIs(caught.exception, commit_interrupt)
            self.assertEqual(calls, 2)
            self.assertEqual(paths[0].read_bytes(), rendered[paths[0]])
            self.assertEqual(paths[1].read_bytes(), b"old\n")
            self.assertEqual(paths[2].read_bytes(), b"old\n")
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_cleanup_retry_preserves_original_control_exception_identity(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = tuple(root / f"{index}.md" for index in range(2))
            rendered = {
                path: f"new-{index}\n".encode()
                for index, path in enumerate(paths)
            }
            for path in paths:
                path.write_bytes(b"old\n")
            original_remove = render_project_status._remove_temporary
            interrupted = False
            injected = KeyboardInterrupt()
            commit_interrupted = False

            def interrupt_cleanup_once(
                cleanup_root: Path,
                path: Path,
            ) -> str | None:
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise SystemExit(23)
                return original_remove(cleanup_root, path)

            def interrupt_commit(source: Path, target: Path) -> None:
                nonlocal commit_interrupted
                if not commit_interrupted:
                    commit_interrupted = True
                    raise injected
                render_project_status._replace_path(root, source, target)

            with (
                mock.patch.object(
                    render_project_status,
                    "_remove_temporary",
                    side_effect=interrupt_cleanup_once,
                ),
                self.assertRaises(BaseException) as caught,
            ):
                render_project_status._write_transaction(
                    root,
                    rendered,
                    replace=interrupt_commit,
                )
            self.assertIs(caught.exception, injected)
            for path in paths:
                self.assertEqual(path.read_bytes(), b"old\n")
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_validation_failure_occurs_before_any_write(self) -> None:
        with (
            mock.patch.object(
                render_project_status,
                "build_rendered_files",
                side_effect=render_project_status.ProjectStatusError("invalid"),
            ),
            mock.patch.object(render_project_status, "_write_transaction") as writer,
        ):
            self.assertEqual(render_project_status.main(["--write"]), 2)
            writer.assert_not_called()

    def test_check_mode_is_green(self) -> None:
        with mock.patch.object(render_project_status, "_verify_git"):
            self.assertEqual(render_project_status.main(["--check"]), 0)


if __name__ == "__main__":
    unittest.main()
