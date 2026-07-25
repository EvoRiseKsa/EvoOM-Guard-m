# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Single-source project-status schema, semantics, and rendering gates."""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from jsonschema import Draft202012Validator

from ops import render_project_status

ROOT = Path(__file__).parents[1]


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
                )
            },
            "sbom_provenance": {},
            "release": {},
        },
    }


class ProjectStatusTests(unittest.TestCase):
    def test_machine_readable_status_matches_its_public_schema(self) -> None:
        status = json.loads((ROOT / "PROJECT_STATUS.json").read_text(encoding="utf-8"))
        schema = json.loads(
            (ROOT / "tests/status/project-status-v1.schema.json").read_text(
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
        v2_status = json.loads(json.dumps(status))
        v2_status["published_release"]["ledger"] = (
            "evidence/release-ledgers/v4.4.0/RELEASE_LEDGER.json"
        )
        self.assertEqual(
            list(Draft202012Validator(schema).iter_errors(v2_status)),
            [],
        )

    def test_project_status_runs_in_matrix_and_has_one_aggregate_check(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        )
        jobs = workflow["jobs"]
        matrix = jobs["test"]["strategy"]["matrix"]["python-version"]
        self.assertEqual(matrix, ["3.10", "3.11", "3.12"])
        runs = [
            step.get("run")
            for step in jobs["test"]["steps"]
            if isinstance(step, dict)
        ]
        self.assertIn("python -I ops/render_project_status.py --check", runs)
        aggregate = jobs["project-status"]
        self.assertEqual(aggregate["needs"], ["test"])
        self.assertEqual(aggregate["if"], "always()")
        self.assertNotIn("strategy", aggregate)

    def test_source_release_and_pipeline_semantics_are_consistent(self) -> None:
        context = render_project_status.load_context(ROOT, verify_git=False)
        self.assertEqual(context.source_version, "4.4.0.dev0")
        self.assertEqual(context.status.lifecycle, "unreleased-development")
        self.assertEqual(context.status.relation, "descendant")
        self.assertEqual(context.ledger.version, "4.3.0")
        self.assertEqual(context.ledger.tag, "v4.3.0")
        self.assertEqual(
            context.ledger.artifacts,
            ("evo-guard.pyz", "SHA256SUMS"),
        )
        self.assertTrue(context.ledger.release_attestation_recorded)
        self.assertTrue(context.ledger.build_provenance_recorded)
        self.assertEqual(
            context.ledger.schema_version,
            "evoguard-release-ledger-v1",
        )
        self.assertFalse(context.ledger.sbom_recorded)
        self.assertFalse(context.ledger.pipeline_operational_evidence_recorded)
        self.assertFalse(context.ledger.pipeline_publication_evidence_recorded)
        self.assertEqual(context.status.cli_extraction, "complete")

    def test_every_supported_status_enum_changes_rendered_truth(self) -> None:
        context = render_project_status.load_context(ROOT, verify_git=False)
        candidate = replace(
            context,
            source_version="4.4.0",
            status=replace(context.status, lifecycle="release-candidate"),
        )
        candidate_summary = render_project_status._release_summary(candidate)
        self.assertIn("release candidate", candidate_summary)
        self.assertNotIn("unreleased development", candidate_summary)
        release_line = replace(
            context,
            source_version="4.3.0",
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
                "4.3.0",
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

    def test_legacy_workflow_rejects_any_unguarded_job(self) -> None:
        spec = render_project_status._LEGACY_SPEC
        text = (ROOT / spec.path).read_text(encoding="utf-8")
        bypass = text.replace(
            f"    if: {render_project_status._LEGACY_FALSE_GATE}\n",
            "",
            1,
        )
        with self.assertRaises(render_project_status.ProjectStatusError):
            render_project_status._verify_workflow_text(
                bypass,
                spec,
                ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"),
            )

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

    def test_v2_requires_real_validator_boundary_and_derives_evidence(self) -> None:
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
            validator.assert_called_once_with(
                root,
                ledger_path.parent,
                "4.4.0",
            )
            self.assertEqual(
                ledger.schema_version,
                "evoguard-release-ledger-v2",
            )
            self.assertEqual(ledger.artifacts, render_project_status._PIPELINE_ASSETS)
            self.assertTrue(ledger.sbom_recorded)
            self.assertTrue(ledger.pipeline_operational_evidence_recorded)
            self.assertTrue(ledger.pipeline_publication_evidence_recorded)

    def test_v2_validation_failure_and_validation_race_fail_closed(self) -> None:
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
            original = json.dumps(_minimal_v2_ledger(), sort_keys=True) + "\n"
            ledger_path.write_text(original, encoding="utf-8")
            status = replace(
                base_context.status,
                ledger_path=ledger_path.relative_to(root).as_posix(),
            )
            with (
                mock.patch.object(
                    render_project_status,
                    "_validate_v2_ledger",
                    side_effect=render_project_status.ProjectStatusError(
                        "validator rejected"
                    ),
                ),
                self.assertRaises(render_project_status.ProjectStatusError),
            ):
                render_project_status._load_ledger(
                    root,
                    status,
                    verify_git=False,
                )

            def mutate(*_arguments: object) -> None:
                ledger_path.write_text(
                    original.replace('"immutable": true', '"immutable": false'),
                    encoding="utf-8",
                )

            with (
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
                render_project_status._load_ledger(
                    root,
                    status,
                    verify_git=False,
                )

    def test_v2_validator_receives_external_key_and_disjoint_parent(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            validator = root / "tools/ci/validate_release_ledger_v2.py"
            trusted_key = (
                root / "security/release-ledger-roots/v4.4.0.pub.pem"
            )
            ledger_directory = (
                root / "evidence/release-ledgers/v4.4.0"
            )
            validator.parent.mkdir(parents=True)
            trusted_key.parent.mkdir(parents=True)
            ledger_directory.mkdir(parents=True)
            validator.write_text("# validator\n", encoding="utf-8")
            trusted_key.write_text("PUBLIC KEY\n", encoding="utf-8")
            calls: list[tuple[tuple[str, ...], Path, str]] = []

            def record(
                command: tuple[str, ...],
                *,
                cwd: Path,
                label: str,
                timeout: int = 120,
            ) -> None:
                del timeout
                calls.append((command, cwd, label))

            with mock.patch.object(
                render_project_status,
                "_run_checked",
                side_effect=record,
            ):
                render_project_status._validate_v2_ledger(
                    root,
                    ledger_directory,
                    "4.4.0",
                )
            self.assertEqual([call[2] for call in calls], [
                "trusted-parent clone",
                "release-ledger-v2 validator",
            ])
            validator_command = calls[1][0]
            self.assertIn(str(trusted_key), validator_command)
            self.assertIn(str(ledger_directory), validator_command)
            parent_index = validator_command.index("--trusted-parent-repo") + 1
            trusted_parent = Path(validator_command[parent_index])
            self.assertFalse(trusted_parent.is_relative_to(root))
            self.assertFalse(trusted_key.is_relative_to(ledger_directory))

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
                    self.assertEqual(len(list(root.rglob("*.tmp"))), 6)
                render_project_status._replace_path(root, source, target)

            render_project_status._write_transaction(
                root,
                rendered,
                replace=verify_stage,
            )
            self.assertFalse(first)

    def test_replace_failure_at_every_position_rolls_back_all_files(self) -> None:
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

                with self.assertRaises(render_project_status.ProjectStatusError):
                    render_project_status._write_transaction(
                        root,
                        rendered,
                        replace=fail_once,
                    )
                self.assertTrue(failed)
                for path, expected in originals.items():
                    self.assertEqual(path.read_bytes(), expected)
                self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_control_baseexception_at_every_replace_rolls_back_with_identity(self) -> None:
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
            for path, expected in originals.items():
                self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_control_baseexception_at_every_staging_point_cleans_and_preserves(self) -> None:
        for failure_position in range(1, 7):
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

    def test_baseexception_during_rollback_is_reported_as_incomplete(self) -> None:
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
            rollback_interrupt = SystemExit(17)
            calls = 0
            commit_failed = False
            rollback_failed = False

            def interrupt_commit_and_rollback(source: Path, target: Path) -> None:
                nonlocal calls, commit_failed, rollback_failed
                calls += 1
                if not commit_failed and calls == 2:
                    commit_failed = True
                    raise commit_interrupt
                if commit_failed and not rollback_failed:
                    rollback_failed = True
                    raise rollback_interrupt
                render_project_status._replace_path(root, source, target)

            with self.assertRaises(
                render_project_status.ProjectStatusError
            ) as caught:
                render_project_status._write_transaction(
                    root,
                    rendered,
                    replace=interrupt_commit_and_rollback,
                )
            self.assertIn("rollback was incomplete", str(caught.exception))
            self.assertIs(caught.exception.__cause__, commit_interrupt)
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
