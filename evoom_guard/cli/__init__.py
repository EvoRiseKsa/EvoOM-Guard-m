# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""The ``evo-guard`` command line for evidence-bound change verification.

Subcommands:

  * ``evo-guard guard`` — verify a candidate change against a repo's selected
    judge, rejecting edits/deletions to the active protected path set.
  * ``evo-guard verify-record`` — verify a verdict's structural/semantic contract.
  * ``evo-guard verify-bundle`` — authenticate a portable verdict envelope.
  * ``evo-guard finalize-record`` — seal a semantic record against trusted context.
  * ``evo-guard finalizer-handoff`` — bind a re-verification record to source metadata.
  * ``evo-guard seal-finalizer`` — sign only a handoff matched to external metadata.
  * ``evo-guard project-change-attempt-observation`` — authenticate a finalizer
    bundle and publish its deterministic advisory-only projection.
  * ``evo-guard release-source-handoff`` — bind a protected-main re-verification
    record to a distinct release-source contract.
  * ``evo-guard seal-release-source-finalizer`` — sign that release-source handoff
    only after an external control plane exactly matches it.
  * ``evo-guard verify-release-source-finalized`` — verify the separate release
    source envelope and its exact control-plane bindings.
  * ``evo-guard derive-release-source-controls`` — derive protected-main source/context
    from raw Git without a checkout.
  * ``evo-guard create-release-source-producer-receipt`` — create a canonical
    non-admitting producer claim for later provider authentication.
  * ``evo-guard verify-release-source-producer-receipt`` — recheck that claim,
    raw-Git bindings, and its exact execution record without contacting a provider.
  * ``evo-guard reverify-attested-release-source-producer-receipt`` — perform
    those checks, then make one fresh constrained GitHub verification.
  * ``evo-guard seal-release-source-admission`` — issue a separately keyed V2
    source ``ALLOW`` only after that fresh provider verification succeeds.
  * ``evo-guard verify-release-source-admission`` — verify the V2 source
    authorization against external source, producer, runtime, policy, and key roots.
  * ``evo-guard seal-github-release-artifact-admission`` — freshly verify and
    seal one protected-main release artifact rooted in a V2 source admission.
  * ``evo-guard verify-github-release-artifact-admission`` — verify that release
    artifact admission and its detached artifact entirely offline.
  * ``evo-guard seal-artifact-admission`` — bind one file to a verified finalizer ALLOW.
  * ``evo-guard verify-artifact-admission`` — verify that file/finalizer binding.
  * ``evo-guard seal-artifact-digest-admission`` — bind one immutable digest to a finalizer.
  * ``evo-guard verify-artifact-digest-admission`` — verify that V2 digest relation.
  * ``evo-guard github-attestation-receipt`` — record one constrained GitHub verification.
  * ``evo-guard verify-github-attestation-receipt`` — check retained attestation bytes.
  * ``evo-guard reverify-github-attestation-receipt`` — make a fresh constrained GitHub check.
  * ``evo-guard seal-github-attestation-admission`` — bind one freshly verified
    GitHub attestation to a Trusted Finalizer ALLOW through the separate V2 key.
  * ``evo-guard verify-github-attestation-admission`` — check that retained V2 relation.
  * ``evo-guard version`` — print the EvoGuard version.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import platform
import re
import shutil
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypedDict, cast

from evoom_guard import __version__
from evoom_guard.cli import agent_change_commands as _agent_change_command_owner
from evoom_guard.cli import artifact_admission_commands as _artifact_admission_command_owner
from evoom_guard.cli import (
    artifact_digest_admission_commands as _artifact_digest_admission_command_owner,
)
from evoom_guard.cli import (
    change_attempt_observation_commands as _change_attempt_observation_command_owner,
)
from evoom_guard.cli import diagnostic_commands as _diagnostic_command_owner
from evoom_guard.cli import (
    finalizer_deployment_commands as _finalizer_deployment_command_owner,
)
from evoom_guard.cli import (
    github_attestation_admission_commands as _github_attestation_admission_command_owner,
)
from evoom_guard.cli import (
    github_attestation_receipt_commands as _github_attestation_receipt_command_owner,
)
from evoom_guard.cli import guard_command as _guard_command_owner
from evoom_guard.cli import init_command as _init_command_owner
from evoom_guard.cli import parser as _parser_owner
from evoom_guard.cli import record_commands as _record_command_owner
from evoom_guard.cli import (
    release_artifact_admission_commands as _release_artifact_admission_command_owner,
)
from evoom_guard.cli import (
    release_source_admission_commands as _release_source_admission_command_owner,
)
from evoom_guard.cli import (
    release_source_finalizer_commands as _release_source_finalizer_command_owner,
)
from evoom_guard.cli import (
    release_source_producer_receipt_commands as _producer_receipt_command_owner,
)
from evoom_guard.cli import signing_commands as _signing_command_owner
from evoom_guard.cli import trusted_finalizer_commands as _trusted_finalizer_command_owner
from evoom_guard.domain import (
    is_verifier_pack_sha256,
    operating_profile_violations,
)
from evoom_guard.pack_manifest import (
    PACK_DIGEST_FORMAT,
    PackManifestError,
    load_pack_manifest,
    pack_digest,
    pack_test_files,
)
from evoom_guard.policy.config import ConfigError
from evoom_guard.policy.config import load_config as _load_config
from evoom_guard.policy.harness import HarnessInputPolicyError

if TYPE_CHECKING:
    from evoom_guard.evidence_bundle import EvidenceMaterial
    from evoom_guard.github_attestation import GitHubAttestationProviderIsolation
    from evoom_guard.guard import GuardResult

MAX_OFFLINE_RECORD_BYTES = 8 * 1024 * 1024
MAX_CONTEXT_INPUT_BYTES = 1 * 1024 * 1024
MAX_SIGNATURE_FILE_BYTES = 4096


class _GitHubAttestationPolicyKwargs(TypedDict):
    """Exact provider-policy keyword arguments shared by CLI adapters.

    A plain ``dict[str, str]`` loses the names of these keys to static type
    checkers.  Keeping the contract explicit prevents a policy string from
    ever being confused with unrelated keyword-only controls such as
    ``force``.
    """

    repository: str
    signer_workflow: str
    signer_digest: str
    source_ref: str
    source_digest: str
    cert_oidc_issuer: str


def _configure_stdio() -> None:
    """Make Unicode verdicts reliable on legacy Windows console code pages."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _read_text(path: str) -> str:
    """Read a file, or stdin when *path* is ``-``."""
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as f:
        return f.read()


def _read_bounded_bytes(path: str, *, limit: int, label: str) -> bytes:
    if path == "-":
        binary = getattr(sys.stdin, "buffer", None)
        data = (
            binary.read(limit + 1)
            if binary is not None
            else sys.stdin.read(limit + 1).encode("utf-8")
        )
    else:
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte input limit")
    return data


_GITHUB_ACTIONS_CREDENTIAL_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_IMMUTABLE_RELEASE_REF_RE = re.compile(r"(?:v\d+\.\d+\.\d+|[0-9a-f]{40})\Z")


def _github_actions_credential_key(value: object) -> str:
    """Validate the *name* of a GitHub Actions credential reference.

    The secret-bearing private scaffold is disabled, but this parser-level
    validation remains for a precise fail-closed compatibility error.
    """
    return _init_command_owner.validate_github_actions_credential_key(
        value,
        credential_name_matches=lambda candidate: (
            _GITHUB_ACTIONS_CREDENTIAL_KEY_RE.fullmatch(candidate) is not None
        ),
    )


def _immutable_release_ref(value: object) -> str:
    """Accept only an exact release tag or full commit SHA for ``init``.

    Workflow scaffolding is a security-sensitive operation: silently choosing a
    branch, an unverified tag, or a stale "latest" value makes the generated
    gate less reproducible than the user believes. This local parser cannot
    establish remote tag availability; it enforces the immutable-reference
    shape and refuses moving branch names. The caller chooses a published tag
    or full commit SHA explicitly.
    """
    if not isinstance(value, str) or _IMMUTABLE_RELEASE_REF_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "--ref must be an exact release tag (vX.Y.Z) or a full 40-hex commit SHA"
        )
    return value


def _path_is_within(path: str, root: str) -> bool:
    """Return whether ``path`` resolves inside ``root``.

    Real paths matter here: a candidate checkout must not be able to smuggle its
    policy in through a symlink when a caller supplied an apparently external
    ``--config`` file.
    """
    try:
        return (
            os.path.commonpath((os.path.realpath(path), os.path.realpath(root)))
            == os.path.realpath(root)
        )
    except ValueError:
        # Different Windows drives, for example, cannot be nested.
        return False


def _config_path_for_guard(args: argparse.Namespace) -> str | None:
    """Resolve the policy file from a trusted side of a change comparison.

    Repository policy can shape the command, protected paths, and assurance
    floor. It must therefore never be read from the candidate checkout. The
    edit-block and ``--base/--head`` forms have an explicit baseline directory,
    so an omitted config resolves there. A unified diff has only a candidate
    checkout; it deliberately gets *no* implicit config. Automation must
    materialize a base-owned policy outside that checkout and pass its absolute
    path explicitly.
    """
    if args.no_config:
        return None

    if args.diff is not None:
        if args.config is None:
            raise ConfigError(
                "--diff requires an explicit trusted --config outside the candidate "
                "checkout, or --no-config"
            )
        if not os.path.isabs(args.config):
            raise ConfigError(
                "--diff requires --config to be an absolute path outside the "
                "candidate checkout (or use --no-config)"
            )
        head = args.repo or os.getcwd()
        if _path_is_within(args.config, head):
            raise ConfigError(
                "--diff refuses a config from the candidate checkout; materialize "
                "the policy from the trusted base outside that checkout"
            )
        return os.path.abspath(args.config)

    if args.base and args.head:
        baseline = args.base
        candidate = args.head
    elif args.repo and args.patch:
        # The patch is text, not a checked-out candidate tree: ``repo`` is the
        # trusted baseline for this input form.
        baseline = args.repo
        candidate = None
    else:
        return None

    if args.config is None:
        config_path = os.path.abspath(os.path.join(baseline, ".evoguard.json"))
        if not _path_is_within(config_path, baseline):
            raise ConfigError(
                "baseline .evoguard.json must resolve inside the trusted baseline "
                "directory"
            )
        return config_path
    if os.path.isabs(args.config):
        if candidate and _path_is_within(args.config, candidate):
            raise ConfigError(
                "--base/--head refuses a config from the candidate checkout; "
                "use the base policy or an external trusted policy file"
            )
        return os.path.abspath(args.config)

    candidate_path = os.path.abspath(os.path.join(baseline, args.config))
    if not _path_is_within(candidate_path, baseline):
        raise ConfigError("--config must stay inside the trusted baseline directory")
    return candidate_path


def _add_github_attestation_policy_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the fixed provider policy inputs; no caller can omit a trust pin."""

    parser.add_argument(
        "--repo",
        required=True,
        help="exact GitHub owner/repository whose artifact attestation is verified",
    )
    parser.add_argument(
        "--signer-workflow",
        required=True,
        help="same-repository workflow path; GitHub URL aliases are normalized before gh",
    )
    parser.add_argument(
        "--signer-digest",
        required=True,
        help="exact lowercase 40- or 64-hex Git object ID for the signer workflow",
    )
    parser.add_argument(
        "--source-ref",
        required=True,
        help="exact canonical refs/heads/... or refs/tags/... source reference",
    )
    parser.add_argument(
        "--source-digest",
        required=True,
        help="exact lowercase 40- or 64-hex Git object ID for the source",
    )
    parser.add_argument(
        "--cert-oidc-issuer",
        required=True,
        help="must be exactly https://token.actions.githubusercontent.com",
    )


def _add_github_attestation_verifier_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--gh-executable",
        default="gh",
        help=(
            "protected GitHub CLI executable (default: gh); local gh config is ignored, "
            "so a protected GH_TOKEN or GITHUB_TOKEN is required"
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=120,
        help="bounded GitHub CLI verification timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--gh-executable-sha256",
        default=None,
        help=(
            "opt-in POSIX isolation: exact lowercase SHA-256 of the absolute "
            "--gh-executable"
        ),
    )
    parser.add_argument(
        "--provider-isolation-uid",
        type=int,
        default=None,
        help="opt-in POSIX isolation: distinct non-root UID for the provider process",
    )
    parser.add_argument(
        "--provider-isolation-gid",
        type=int,
        default=None,
        help="opt-in POSIX isolation: distinct non-root GID for the provider process",
    )


def _add_release_artifact_key_registry_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    """Add the five earlier public roots required by the RAAE key registry."""

    parser.add_argument(
        "--trusted-finalizer-pub",
        required=True,
        help="public key for the Trusted Finalizer domain",
    )
    parser.add_argument(
        "--artifact-admission-v1-pub",
        required=True,
        help="public key for Artifact Admission V1",
    )
    parser.add_argument(
        "--artifact-digest-admission-v2-pub",
        required=True,
        help="public key for Artifact Digest Admission V2 / GitHub bridge",
    )
    parser.add_argument(
        "--release-source-finalizer-v1-pub",
        required=True,
        help="public key for the DENY-only Release Source Finalizer V1",
    )
    parser.add_argument(
        "--release-source-admission-v2-pub",
        required=True,
        help=(
            "trusted V2 release-source admission public key and fifth earlier "
            "RAAE trust root"
        ),
    )


def _add_nested_release_source_expectation_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    """Add exact external RSAE expectations without conflating outer RAAE pins."""

    parser.add_argument(
        "--expected-release-source",
        required=True,
        help="external protected-main release-source JSON",
    )
    parser.add_argument(
        "--expected-release-source-context",
        required=True,
        help="external release-source context JSON",
    )
    parser.add_argument(
        "--expected-release-source-producer",
        required=True,
        help="external release-source producer identity JSON",
    )
    parser.add_argument(
        "--expected-release-source-admitter",
        required=True,
        help="external protected C workflow identity JSON",
    )
    parser.add_argument(
        "--expected-release-source-bootstrap-guard-sha",
        required=True,
        help="external SHA-256 of the immutable Guard runtime embedded by the RSAE",
    )
    parser.add_argument(
        "--expected-release-source-github-policy",
        required=True,
        help="external GitHub policy JSON for the embedded release-source admission",
    )
    parser.add_argument(
        "--expected-release-source-git-executable-sha256",
        required=True,
        help="external RSAE Git executable SHA-256 pin",
    )
    parser.add_argument(
        "--expected-release-source-gh-executable-sha256",
        required=True,
        help="external RSAE GitHub CLI executable SHA-256 pin",
    )
    parser.add_argument(
        "--expected-release-source-provider-isolation-uid",
        required=True,
        type=int,
        help="external RSAE provider-isolation POSIX UID",
    )
    parser.add_argument(
        "--expected-release-source-provider-isolation-gid",
        required=True,
        type=int,
        help="external RSAE provider-isolation POSIX GID",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the public parser through the extracted declarative owner."""

    return _parser_owner.build_parser(
        immutable_release_ref_provider=lambda: _immutable_release_ref,
        add_github_attestation_policy_arguments=lambda parser: (
            _add_github_attestation_policy_arguments(parser)
        ),
        add_github_attestation_verifier_arguments=lambda parser: (
            _add_github_attestation_verifier_arguments(parser)
        ),
        add_release_artifact_key_registry_arguments=lambda parser: (
            _add_release_artifact_key_registry_arguments(parser)
        ),
        add_nested_release_source_expectation_arguments=lambda parser: (
            _add_nested_release_source_expectation_arguments(parser)
        ),
    )




def _guard_command_services() -> _guard_command_owner.GuardCommandServices[GuardResult]:
    """Snapshot entry-time Guard imports and inject call-time facade seams."""

    from evoom_guard.guard import (
        REASON_NO_VERIFIABLE_CHANGES,
        REASON_VERIFIER_PACK_INVALID,
        _UnverifiableChangedPathsError,
        blocks_from_dirs,
        build_effective_policy_payload,
        guard,
        guard_from_diff,
        input_error_result,
        render_report,
        serialize_candidate_blocks,
        verifier_pack_trust_error,
        write_json,
        write_sarif,
    )
    from evoom_guard.integrations.guard_output import write_markdown

    def write_report(path: str, report: str) -> None:
        write_markdown(report + "\n", path)

    def sign_file_provider() -> Callable[[str, str], str]:
        from evoom_guard.signing import sign_file

        return sign_file

    return _guard_command_owner.GuardCommandServices(
        config_path_for_guard=lambda args: _config_path_for_guard(args),
        load_config=lambda path, *, required, out: _load_config(
            path, required=required, out=out
        ),
        config_error_type=lambda: ConfigError,
        read_text=lambda path: _read_text(path),
        path_is_absolute=lambda path: os.path.isabs(path),
        absolute_path=lambda path: os.path.abspath(path),
        directory_name=lambda path: os.path.dirname(path),
        join_path=lambda *parts: os.path.join(*parts),
        current_directory=lambda: os.getcwd(),
        path_is_file=lambda path: os.path.isfile(path),
        is_hex_sha256=lambda value: is_verifier_pack_sha256(value),
        is_finite=lambda value: math.isfinite(value),
        no_verifiable_changes_reason=REASON_NO_VERIFIABLE_CHANGES,
        invalid_verifier_pack_reason=REASON_VERIFIER_PACK_INVALID,
        unverifiable_changed_paths_error=_UnverifiableChangedPathsError,
        blocks_from_dirs=blocks_from_dirs,
        guard=guard,
        guard_from_diff=guard_from_diff,
        input_error_result=input_error_result,
        render_report=render_report,
        serialize_candidate_blocks=serialize_candidate_blocks,
        verifier_pack_trust_error=verifier_pack_trust_error,
        write_json=write_json,
        write_sarif=write_sarif,
        write_report=write_report,
        sign_file_provider=sign_file_provider,
        operating_profile_violations=operating_profile_violations,
        effective_policy=build_effective_policy_payload,
    )


def cmd_guard(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard guard`` through the extracted typed owner."""

    try:
        return _guard_command_owner.execute_guard_command(
            args,
            services=_guard_command_services(),
            out=out,
        )
    except HarnessInputPolicyError as exc:
        out(f"usage: invalid trusted harness_inputs policy: {exc}")
        return 2


def doctor_report() -> dict[str, object]:
    """The environment EvoGuard depends on, as a stable dict (see ``evo-guard doctor``).

    ``git``/``patch`` are the only host tools the gate shells out to (for
    ``--diff`` reverse-apply); ``supported`` is true when at least one is present.
    """
    return _diagnostic_command_owner.build_doctor_report(
        _diagnostic_command_owner.DoctorServices(
            version=lambda: __version__,
            platform_name=lambda: sys.platform,
            machine=lambda: platform.machine(),
            python_version=lambda: platform.python_version(),
            which=lambda name: shutil.which(name),
        )
    )


def cmd_doctor(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard doctor`` — report the environment; exit 0 only if supported."""
    return _diagnostic_command_owner.execute_doctor(
        args,
        report_provider=lambda: doctor_report(),
        json_dumps=lambda value, **kwargs: json.dumps(value, **kwargs),
        out=out,
    )


def cmd_finalizer_init(
    args: argparse.Namespace, *, out: Callable[[str], None] = print
) -> int:
    """Install the deterministic, no-clobber Trusted Finalizer deployment kit."""

    from evoom_guard.finalizer.deployment import (
        FinalizerDeploymentError,
        install_finalizer_deployment,
    )

    return _finalizer_deployment_command_owner.execute_finalizer_init(
        args,
        installer=install_finalizer_deployment,
        error_type=FinalizerDeploymentError,
        json_dumps=lambda value, **kwargs: json.dumps(value, **kwargs),
        out=out,
    )


def cmd_finalizer_doctor(
    args: argparse.Namespace, *, out: Callable[[str], None] = print
) -> int:
    """Inspect static finalizer inputs without claiming live GitHub readiness."""

    from evoom_guard.finalizer.deployment import inspect_finalizer_deployment

    return _finalizer_deployment_command_owner.execute_finalizer_doctor(
        args,
        inspector=inspect_finalizer_deployment,
        json_dumps=lambda value, **kwargs: json.dumps(value, **kwargs),
        out=out,
    )


def _workflow_yaml(ref: str) -> str:
    """The EvoGuard GitHub Actions workflow that ``evo-guard init`` scaffolds.

    Pins the action to ``ref`` (the matching release tag by default). The judge
    command belongs in the base-owned ``.evoguard.json`` policy rather than the
    candidate-controlled pull-request workflow.
    """
    return _init_command_owner.render_public_workflow(ref)


def _workflow_yaml_private(ref: str, credential_key: str = "EVOGUARD_TOKEN") -> str:
    """Refuse the historical secret-bearing private pull-request scaffold."""
    return _init_command_owner.render_private_workflow(ref, credential_key)


def _default_policy_path(workflow_path: str) -> str:
    """Infer a repository-root policy path from the conventional workflow path."""
    return _init_command_owner.infer_default_policy_path(
        workflow_path,
        services=_init_command_owner.InitPathServices(
            absolute_path_provider=lambda: os.path.abspath,
            directory_name_provider=lambda: os.path.dirname,
            base_name_provider=lambda: os.path.basename,
            join_path_provider=lambda: cast(Any, os.path.join),
            current_directory_provider=lambda: os.getcwd,
        ),
    )


def _init_command_services() -> _init_command_owner.InitCommandServices:
    """Inject providers for each historically live initialization callable."""

    return _init_command_owner.InitCommandServices(
        validate_credential_key_provider=lambda: _github_actions_credential_key,
        render_public_workflow_provider=lambda: _workflow_yaml,
        render_private_workflow_provider=lambda: _workflow_yaml_private,
        default_policy_path_provider=lambda: _default_policy_path,
        path_exists_provider=lambda: os.path.exists,
        directory_name_provider=lambda: os.path.dirname,
        make_directories_provider=lambda: cast(Any, os.makedirs),
        open_text_provider=lambda: cast(Any, open),
        dump_json_provider=lambda: cast(Any, json.dump),
    )


def cmd_init(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard init`` — scaffold a ready-to-use GitHub Actions workflow.

    Writes the workflow and, when absent, a trusted ``.evoguard.json`` policy.
    The workflow is refused when it exists unless ``--force`` is given; an
    existing policy is deliberately preserved so initialization cannot erase an
    adopter's judge contract. ``--stdout`` prints only the workflow.
    ``--private-evoguard`` is retained only to return a fail-closed migration
    message; candidate-controlled workflow YAML must never receive the private
    repository credential.
    """
    return _init_command_owner.execute_init_command(
        args,
        services=_init_command_services(),
        out=out,
    )


def cmd_keygen(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard keygen`` — generate an Ed25519 signing keypair."""
    from evoom_guard.signing import generate_keypair

    return _signing_command_owner.execute_keygen(
        args,
        services=_signing_command_owner.KeygenServices(
            generate_keypair=generate_keypair,
        ),
        out=out,
    )


def cmd_verify_verdict(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard verify-verdict`` — signature + CONTEXT check (exit 0/1).

    A valid signature only proves the verdict bytes did not change after
    signing. The optional ``--expect-*`` flags make the check *contextual*:
    a perfectly signed verdict for the WRONG commit / policy fails — which is
    what a merge or deploy gate actually needs (chain of custody, not just
    file integrity).
    """

    from evoom_guard.signing import SigningUnavailableError, verify_bytes

    def strict_json_loads_provider() -> Callable[[str], Any]:
        from evoom_guard.record_verifier import strict_json_loads

        return strict_json_loads

    return _record_command_owner.execute_verify_verdict(
        args,
        services=_record_command_owner.VerifyVerdictServices(
            read_bounded_bytes=lambda path, *, limit, label: _read_bounded_bytes(
                path,
                limit=limit,
                label=label,
            ),
            decode_signature=lambda encoded: base64.b64decode(
                encoded,
                validate=True,
            ),
            verify_bytes=verify_bytes,
            input_errors=(
                OSError,
                ValueError,
                binascii.Error,
                SigningUnavailableError,
            ),
            sha256_hex=lambda payload: hashlib.sha256(payload).hexdigest(),
            strict_json_loads_provider=strict_json_loads_provider,
            max_record_bytes=MAX_OFFLINE_RECORD_BYTES,
            max_signature_bytes=MAX_SIGNATURE_FILE_BYTES,
        ),
        out=out,
    )


def cmd_verify_record(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Validate record semantics and emit one machine-readable JSON report.

    This command intentionally leaves signature verification to
    :func:`cmd_verify_verdict`.  Exit 0 means no semantic contradiction was
    found, exit 1 means a well-formed JSON value failed validation, and exit 2
    means the input could not be read as JSON.
    """

    from evoom_guard.record_verifier import (
        invalid_json_report,
        strict_json_loads,
        verify_record,
    )

    return _record_command_owner.execute_verify_record(
        args,
        services=_record_command_owner.VerifyRecordServices(
            read_bounded_bytes=lambda path, *, limit, label: _read_bounded_bytes(
                path,
                limit=limit,
                label=label,
            ),
            strict_json_loads=strict_json_loads,
            verify_record=verify_record,
            invalid_json_report=invalid_json_report,
            sha256_hex=lambda payload: hashlib.sha256(payload).hexdigest(),
            render_report=lambda report: json.dumps(
                report,
                indent=2,
                sort_keys=True,
            ),
            max_record_bytes=MAX_OFFLINE_RECORD_BYTES,
        ),
        out=out,
    )


def _machine_report(out: Callable[[str], None], value: dict[str, object]) -> None:
    out(json.dumps(value, indent=2, sort_keys=True))


def cmd_bundle_evidence(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Create a signed envelope only after semantic record validation succeeds."""

    from evoom_guard.evidence_bundle import (
        EvidenceBundleError,
        EvidenceMaterial,
        create_evidence_bundle,
    )
    from evoom_guard.record_verifier import strict_json_loads, verify_record
    from evoom_guard.signing import SigningUnavailableError

    return _record_command_owner.execute_bundle_evidence(
        args,
        services=_record_command_owner.BundleEvidenceServices(
            read_bounded_bytes=lambda path, *, limit, label: _read_bounded_bytes(
                path,
                limit=limit,
                label=label,
            ),
            strict_json_loads=strict_json_loads,
            verify_record=verify_record,
            evidence_material=EvidenceMaterial,
            create_evidence_bundle=create_evidence_bundle,
            invalid_input_errors=(EvidenceBundleError,),
            operational_errors=(OSError, ValueError, SigningUnavailableError),
            machine_report=lambda reporter, value: _machine_report(
                reporter,
                value,
            ),
            canonical_manifest_bytes=lambda manifest: (
                json.dumps(
                    manifest,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                )
                + "\n"
            ).encode("ascii"),
            sha256_hex=lambda payload: hashlib.sha256(payload).hexdigest(),
            absolute_path=lambda path: os.path.abspath(path),
            max_record_bytes=MAX_OFFLINE_RECORD_BYTES,
            max_context_bytes=MAX_CONTEXT_INPUT_BYTES,
        ),
        out=out,
    )


def cmd_finalize_record(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Seal a semantic record against trusted context and expose ALLOW/DENY.

    The command is deliberately not an execution verifier: its context must be
    derived by a trusted finalizer from the control plane, after an isolated
    re-verification.  It never upgrades a PR artifact into a trusted runtime
    observation by itself.
    """

    from evoom_guard.evidence_bundle import (
        EvidenceBundleError,
        EvidenceMaterial,
        finalize_evidence_bundle,
    )
    from evoom_guard.record_verifier import strict_json_loads, verify_record
    from evoom_guard.signing import SigningUnavailableError

    return _record_command_owner.execute_finalize_record(
        args,
        services=_record_command_owner.FinalizeRecordServices(
            read_bounded_bytes=lambda path, *, limit, label: _read_bounded_bytes(
                path,
                limit=limit,
                label=label,
            ),
            strict_json_loads=strict_json_loads,
            verify_record=verify_record,
            evidence_material=EvidenceMaterial,
            finalize_evidence_bundle=finalize_evidence_bundle,
            invalid_input_errors=(EvidenceBundleError,),
            operational_errors=(OSError, ValueError, SigningUnavailableError),
            machine_report=lambda reporter, value: _machine_report(
                reporter,
                value,
            ),
            canonical_manifest_bytes=lambda manifest: (
                json.dumps(
                    manifest,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                )
                + "\n"
            ).encode("ascii"),
            sha256_hex=lambda payload: hashlib.sha256(payload).hexdigest(),
            max_record_bytes=MAX_OFFLINE_RECORD_BYTES,
            max_context_bytes=MAX_CONTEXT_INPUT_BYTES,
        ),
        out=out,
    )


def _read_external_finalizer_object(path: str, *, label: str) -> dict[str, object]:
    """Read a bounded JSON object supplied outside candidate-controlled artifacts."""

    from evoom_guard.evidence_bundle import (
        EvidenceBundleError,
    )
    from evoom_guard.evidence_bundle import (
        read_regular_file_bytes as _read_regular_file,
    )
    from evoom_guard.record_verifier import strict_json_loads

    if path == "-":
        raise ValueError(f"{label} must be a regular JSON file, not standard input")
    try:
        data = _read_regular_file(path, limit=MAX_CONTEXT_INPUT_BYTES, label=label)
    except EvidenceBundleError as exc:
        raise ValueError(str(exc)) from exc
    value = strict_json_loads(data.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} JSON must be an object")
    return value


def _parse_finalizer_materials(specifications: list[str]) -> list[EvidenceMaterial]:
    """Parse bounded material declarations shared by the finalizer commands."""

    from evoom_guard.evidence_bundle import EvidenceMaterial

    materials: list[EvidenceMaterial] = []
    for specification in specifications:
        role, separator, path = specification.partition("=")
        if not separator or not role or not path:
            raise ValueError(
                f"invalid --material {specification!r}; expected ROLE=PATH"
            )
        materials.append(EvidenceMaterial(role=role, source_path=path))
    return materials


def cmd_derive_finalizer_bindings(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Derive trusted-finalizer values from raw Git objects without a checkout."""

    from evoom_guard.finalizer_derivation import (
        FINALIZER_DERIVATION_FORMAT,
        FinalizerDerivationError,
        derive_finalizer_bindings,
        write_finalizer_bindings,
    )

    return _trusted_finalizer_command_owner.execute_derive_finalizer_bindings(
        args,
        services=_trusted_finalizer_command_owner.DeriveBindingsServices(
            derivation_format=FINALIZER_DERIVATION_FORMAT,
            expected_errors=(
                FinalizerDerivationError,
                OSError,
                UnicodeError,
                ValueError,
            ),
            derive_bindings=derive_finalizer_bindings,
            write_bindings=write_finalizer_bindings,
            machine_report=lambda report_out, value: _machine_report(
                report_out,
                value,
            ),
        ),
        out=out,
    )


def cmd_validate_agent_change_proposal(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    from evoom_guard.admission.agent_change import (
        AGENT_CHANGE_PROPOSAL_FORMAT,
        AgentChangeAdmissionError,
        inspect_agent_change_proposal,
    )

    return _agent_change_command_owner.execute_validate_agent_change_proposal(
        args,
        services=_agent_change_command_owner.ValidateProposalServices(
            proposal_format=AGENT_CHANGE_PROPOSAL_FORMAT,
            expected_errors=(
                AgentChangeAdmissionError,
                OSError,
                UnicodeError,
                ValueError,
            ),
            inspect_proposal=inspect_agent_change_proposal,
            machine_report=lambda report_out, value: _machine_report(
                report_out,
                value,
            ),
        ),
        out=out,
    )


def cmd_derive_agent_change_bindings(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    from evoom_guard.finalizer_derivation import (
        AGENT_CHANGE_GIT_BINDINGS_FORMAT,
        FinalizerDerivationError,
        derive_agent_change_bindings,
        git_executable_pin,
        write_agent_change_bindings,
    )

    return _agent_change_command_owner.execute_derive_agent_change_bindings(
        args,
        services=_agent_change_command_owner.DeriveBindingsServices(
            bindings_format=AGENT_CHANGE_GIT_BINDINGS_FORMAT,
            expected_errors=(
                FinalizerDerivationError,
                OSError,
                UnicodeError,
                ValueError,
            ),
            git_executable_pin=git_executable_pin,
            derive_bindings=derive_agent_change_bindings,
            write_bindings=write_agent_change_bindings,
            machine_report=lambda report_out, value: _machine_report(
                report_out,
                value,
            ),
        ),
        out=out,
    )


def cmd_seal_agent_change_authorization(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    from evoom_guard.admission.agent_change import (
        AGENT_CHANGE_AUTHORIZATION_FORMAT,
        AgentChangeAdmissionError,
        seal_agent_change_authorization,
    )

    return _agent_change_command_owner.execute_seal_agent_change_authorization(
        args,
        services=_agent_change_command_owner.SealAuthorizationServices(
            authorization_format=AGENT_CHANGE_AUTHORIZATION_FORMAT,
            expected_errors=(
                AgentChangeAdmissionError,
                OSError,
                UnicodeError,
                ValueError,
            ),
            read_external_object=lambda path, *, label: _read_external_finalizer_object(
                path, label=label
            ),
            seal_authorization=seal_agent_change_authorization,
            absolute_path=lambda path: os.path.abspath(path),
            machine_report=lambda report_out, value: _machine_report(
                report_out,
                value,
            ),
        ),
        out=out,
    )


def cmd_seal_agent_change_finalized(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    from evoom_guard.admission.agent_change import (
        AGENT_CHANGE_PROPOSAL_FORMAT,
        AgentChangeAdmissionError,
        seal_agent_change_finalizer_bundle,
    )
    from evoom_guard.finalizer_derivation import (
        FinalizerDerivationError,
        git_executable_pin,
        read_finalizer_bindings,
    )

    return _agent_change_command_owner.execute_seal_agent_change_finalized(
        args,
        services=_agent_change_command_owner.SealFinalizedServices(
            proposal_format=AGENT_CHANGE_PROPOSAL_FORMAT,
            expected_errors=(
                AgentChangeAdmissionError,
                FinalizerDerivationError,
                OSError,
                UnicodeError,
                ValueError,
            ),
            git_executable_pin=git_executable_pin,
            read_finalizer_bindings=read_finalizer_bindings,
            read_external_object=lambda path, *, label: _read_external_finalizer_object(
                path, label=label
            ),
            seal_finalized=seal_agent_change_finalizer_bundle,
            machine_report=lambda report_out, value: _machine_report(
                report_out,
                value,
            ),
        ),
        out=out,
    )


def cmd_verify_agent_change_finalized(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    from evoom_guard.admission.agent_change import (
        AGENT_CHANGE_PROPOSAL_FORMAT,
        AgentChangeAdmissionError,
        verify_agent_change_finalized_bundle,
    )
    from evoom_guard.finalizer_derivation import (
        FinalizerDerivationError,
        read_agent_change_bindings,
    )

    return _agent_change_command_owner.execute_verify_agent_change_finalized(
        args,
        services=_agent_change_command_owner.VerifyFinalizedServices(
            proposal_format=AGENT_CHANGE_PROPOSAL_FORMAT,
            expected_errors=(
                AgentChangeAdmissionError,
                FinalizerDerivationError,
                OSError,
                UnicodeError,
                ValueError,
            ),
            read_agent_bindings=read_agent_change_bindings,
            read_external_object=lambda path, *, label: _read_external_finalizer_object(
                path, label=label
            ),
            verify_finalized=verify_agent_change_finalized_bundle,
            machine_report=lambda report_out, value: _machine_report(
                report_out,
                value,
            ),
        ),
        out=out,
    )


def _read_semantic_finalizer_record(path: str) -> dict[str, Any]:
    """Read and validate one untrusted verdict before using its digest fields."""

    from evoom_guard.evidence_bundle import (
        MAX_VERDICT_BYTES,
        snapshot_evidence_primitives,
    )
    from evoom_guard.record_verifier import verify_record

    evidence_primitives = snapshot_evidence_primitives()

    return _trusted_finalizer_command_owner.execute_read_semantic_finalizer_record(
        path,
        services=_trusted_finalizer_command_owner.SemanticRecordServices(
            max_verdict_bytes=MAX_VERDICT_BYTES,
            read_regular_file=evidence_primitives.read_regular_file,
            load_json_object=evidence_primitives.load_json_object,
            verify_record=verify_record,
        ),
    )


def cmd_verify_finalizer_bindings(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Compare a semantic record to independently derived raw-Git bindings."""

    from evoom_guard.finalizer_derivation import (
        FINALIZER_DERIVATION_FORMAT,
        FinalizerDerivationError,
        context_from_verified_bindings,
        read_finalizer_bindings,
        write_verified_finalizer_context,
    )

    return _trusted_finalizer_command_owner.execute_verify_finalizer_bindings(
        args,
        services=_trusted_finalizer_command_owner.VerifyBindingsServices(
            derivation_format=FINALIZER_DERIVATION_FORMAT,
            expected_errors=(
                FinalizerDerivationError,
                OSError,
                UnicodeError,
                ValueError,
            ),
            read_bindings=read_finalizer_bindings,
            read_semantic_record=lambda record_path: _read_semantic_finalizer_record(
                record_path
            ),
            context_from_bindings=context_from_verified_bindings,
            write_verified_context=write_verified_finalizer_context,
            machine_report=lambda report_out, value: _machine_report(
                report_out,
                value,
            ),
        ),
        out=out,
    )


def cmd_finalizer_handoff(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Bind a semantic re-verification record to explicit trusted metadata."""

    from evoom_guard.evidence_bundle import EvidenceBundleError
    from evoom_guard.trusted_finalizer import (
        FinalizerHandoffError,
        create_finalizer_handoff,
    )

    return _trusted_finalizer_command_owner.execute_finalizer_handoff(
        args,
        services=_trusted_finalizer_command_owner.FinalizerHandoffServices(
            metadata_errors=(OSError, UnicodeError, ValueError),
            invalid_input_errors=(EvidenceBundleError, FinalizerHandoffError),
            operational_errors=(OSError,),
            read_external_object=lambda object_path, *, label: (
                _read_external_finalizer_object(object_path, label=label)
            ),
            create_handoff=create_finalizer_handoff,
            absolute_path=lambda output_path: os.path.abspath(output_path),
            machine_report=lambda report_out, value: _machine_report(
                report_out,
                value,
            ),
        ),
        out=out,
    )


def cmd_seal_finalizer(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Seal only a handoff that matches externally re-derived metadata."""

    from evoom_guard.evidence_bundle import EvidenceBundleError
    from evoom_guard.finalizer_derivation import read_finalizer_bindings
    from evoom_guard.signing import SigningUnavailableError
    from evoom_guard.trusted_finalizer import FinalizerHandoffError, seal_finalizer_bundle

    return _trusted_finalizer_command_owner.execute_seal_finalizer(
        args,
        services=_trusted_finalizer_command_owner.SealFinalizerServices(
            trusted_input_errors=(OSError, UnicodeError, ValueError),
            invalid_input_errors=(EvidenceBundleError, FinalizerHandoffError),
            operational_errors=(OSError, ValueError, SigningUnavailableError),
            read_external_object=lambda object_path, *, label: (
                _read_external_finalizer_object(object_path, label=label)
            ),
            read_bindings=read_finalizer_bindings,
            parse_materials=lambda values: _parse_finalizer_materials(values),
            seal_finalizer=seal_finalizer_bundle,
            machine_report=lambda report_out, value: _machine_report(
                report_out,
                value,
            ),
        ),
        out=out,
    )


def cmd_verify_finalized(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify a signed finalizer bundle and all external anti-replay bindings."""

    from evoom_guard.signing import SigningUnavailableError
    from evoom_guard.trusted_finalizer import (
        FinalizerHandoffError,
        verify_finalized_bundle,
    )

    return _trusted_finalizer_command_owner.execute_verify_finalized(
        args,
        services=_trusted_finalizer_command_owner.VerifyFinalizedServices(
            external_input_errors=(OSError, UnicodeError, ValueError),
            signing_unavailable_errors=(SigningUnavailableError,),
            invalid_bundle_errors=(OSError, ValueError, FinalizerHandoffError),
            read_external_object=lambda object_path, *, label: (
                _read_external_finalizer_object(object_path, label=label)
            ),
            verify_finalized=verify_finalized_bundle,
            machine_report=lambda report_out, value: _machine_report(
                report_out,
                value,
            ),
        ),
        out=out,
    )


def cmd_project_change_attempt_observation(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Authenticate one finalizer bundle and publish an advisory projection."""

    from evoom_guard.change_attempt_observation import (
        ChangeAttemptObservationError,
        produce_change_attempt_observation,
    )
    from evoom_guard.signing import SigningUnavailableError

    return (
        _change_attempt_observation_command_owner
        .execute_project_change_attempt_observation(
            args,
            services=(
                _change_attempt_observation_command_owner.ProjectObservationServices(
                    read_external_object=lambda object_path, *, label: (
                        _read_external_finalizer_object(object_path, label=label)
                    ),
                    project_observation=produce_change_attempt_observation,
                    invalid_errors=(ChangeAttemptObservationError,),
                    operational_errors=(OSError, SigningUnavailableError),
                    machine_report=lambda report_out, value: _machine_report(
                        report_out,
                        value,
                    ),
                    absolute_path=os.path.abspath,
                )
            ),
            out=out,
        )
    )


def cmd_release_source_handoff(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Write an unsigned handoff for the separate protected-main contract."""

    from evoom_guard.release_source_finalizer import (
        RELEASE_SOURCE_HANDOFF_FORMAT,
        ReleaseSourceFinalizerError,
        create_release_source_handoff,
    )

    return _release_source_finalizer_command_owner.execute_release_source_handoff(
        args,
        services=(
            _release_source_finalizer_command_owner.ReleaseSourceHandoffServices(
                handoff_format=RELEASE_SOURCE_HANDOFF_FORMAT,
                finalizer_error=ReleaseSourceFinalizerError,
                create_release_source_handoff=create_release_source_handoff,
                read_external_object_provider=lambda: (
                    _read_external_finalizer_object
                ),
                absolute_path_provider=lambda: os.path.abspath,
                machine_report_provider=lambda: _machine_report,
            )
        ),
        out=out,
    )


def cmd_seal_release_source_finalizer(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Seal a protected-main handoff only after external source matching."""

    from evoom_guard.release_source_finalizer import (
        RELEASE_SOURCE_EVIDENCE_FORMAT,
        ReleaseSourceFinalizerError,
        seal_release_source_bundle,
    )
    from evoom_guard.signing import SigningUnavailableError

    return _release_source_finalizer_command_owner.execute_seal_release_source_finalizer(
        args,
        services=(
            _release_source_finalizer_command_owner.SealReleaseSourceFinalizerServices(
                evidence_format=RELEASE_SOURCE_EVIDENCE_FORMAT,
                finalizer_error=ReleaseSourceFinalizerError,
                signing_unavailable_error=SigningUnavailableError,
                seal_release_source_bundle=seal_release_source_bundle,
                read_external_object_provider=lambda: (
                    _read_external_finalizer_object
                ),
                machine_report_provider=lambda: _machine_report,
            )
        ),
        out=out,
    )


def cmd_verify_release_source_finalized(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify a separate release-source envelope and external bindings."""

    from evoom_guard.release_source_finalizer import (
        RELEASE_SOURCE_EVIDENCE_FORMAT,
        ReleaseSourceFinalizerError,
        verify_release_source_bundle,
    )
    from evoom_guard.signing import SigningUnavailableError

    return _release_source_finalizer_command_owner.execute_verify_release_source_finalized(
        args,
        services=(
            _release_source_finalizer_command_owner.VerifyReleaseSourceFinalizedServices(
                evidence_format=RELEASE_SOURCE_EVIDENCE_FORMAT,
                finalizer_error=ReleaseSourceFinalizerError,
                signing_unavailable_error=SigningUnavailableError,
                verify_release_source_bundle=verify_release_source_bundle,
                read_external_object_provider=lambda: (
                    _read_external_finalizer_object
                ),
                machine_report_provider=lambda: _machine_report,
            )
        ),
        out=out,
    )


def cmd_derive_release_source_controls(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Re-derive source/context from raw Git without making an admission claim."""

    from evoom_guard.evidence_bundle import snapshot_evidence_primitives
    from evoom_guard.release_source_finalizer import (
        RELEASE_SOURCE_CONTEXT_FORMAT,
        ReleaseSourceFinalizerError,
        snapshot_release_source_finalizer_primitives,
    )

    finalizer_primitives = snapshot_release_source_finalizer_primitives()
    evidence_primitives = snapshot_evidence_primitives()

    def canonical_json(value: dict[str, Any]) -> bytes:
        return evidence_primitives.canonical_json(value)

    return _release_source_finalizer_command_owner.execute_derive_release_source_controls(
        args,
        services=(
            _release_source_finalizer_command_owner.DeriveReleaseSourceControlsServices(
                context_format=RELEASE_SOURCE_CONTEXT_FORMAT,
                finalizer_error=ReleaseSourceFinalizerError,
                canonical_json=canonical_json,
                publish_bytes=finalizer_primitives.publish_bytes,
                record_snapshot=finalizer_primitives.record_snapshot,
                context_from_release_source_bindings=(
                    finalizer_primitives.context_from_release_source_bindings
                ),
                derive_release_source_bindings=(
                    finalizer_primitives.derive_release_source_bindings
                ),
                read_external_object_provider=lambda: (
                    _read_external_finalizer_object
                ),
                absolute_path_provider=lambda: os.path.abspath,
                machine_report_provider=lambda: _machine_report,
            )
        ),
        out=out,
    )


def cmd_create_release_source_producer_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Create an unsigned canonical claim; it is never an admission decision."""

    from evoom_guard.release_source_producer_receipt import (
        RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
        ReleaseSourceProducerReceiptError,
        create_release_source_producer_receipt,
    )

    return _producer_receipt_command_owner.execute_create_producer_receipt(
        args,
        services=_producer_receipt_command_owner.CreateProducerReceiptServices(
            receipt_format=RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
            producer_error=ReleaseSourceProducerReceiptError,
            create_producer_receipt=create_release_source_producer_receipt,
            read_external_object_provider=lambda: _read_external_finalizer_object,
            absolute_path_provider=lambda: os.path.abspath,
            machine_report_provider=lambda: _machine_report,
        ),
        out=out,
    )


def _producer_receipt_external_inputs(args: argparse.Namespace) -> tuple[
    dict[str, object], dict[str, object], dict[str, object]
]:
    return (
        _read_external_finalizer_object(args.source, label="expected release source"),
        _read_external_finalizer_object(args.context, label="expected release-source context"),
        _read_external_finalizer_object(args.producer, label="expected producer identity"),
    )


def cmd_verify_release_source_producer_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify local/raw-Git producer binding without treating it as provider proof."""

    from evoom_guard.release_source_producer_receipt import (
        RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
        ReleaseSourceProducerReceiptError,
        verify_release_source_producer_receipt,
    )

    return _producer_receipt_command_owner.execute_verify_producer_receipt(
        args,
        services=_producer_receipt_command_owner.VerifyProducerReceiptServices(
            receipt_format=RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
            producer_error=ReleaseSourceProducerReceiptError,
            verify_producer_receipt=verify_release_source_producer_receipt,
            external_inputs_provider=lambda: _producer_receipt_external_inputs,
            machine_report_provider=lambda: _machine_report,
        ),
        out=out,
    )


def cmd_reverify_attested_release_source_producer_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Make a fresh GitHub provider check after local/raw-Git verification."""

    from evoom_guard.release_source_producer_receipt import (
        RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
        ReleaseSourceProducerReceiptError,
        reverify_attested_release_source_producer_receipt,
    )

    return _producer_receipt_command_owner.execute_reverify_producer_receipt(
        args,
        services=_producer_receipt_command_owner.ReverifyProducerReceiptServices(
            receipt_format=RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
            producer_error=ReleaseSourceProducerReceiptError,
            reverify_producer_receipt=(
                reverify_attested_release_source_producer_receipt
            ),
            external_inputs_provider=lambda: _producer_receipt_external_inputs,
            read_external_object_provider=lambda: _read_external_finalizer_object,
            machine_report_provider=lambda: _machine_report,
        ),
        out=out,
    )


def _release_source_key_separation(args: argparse.Namespace) -> dict[str, str]:
    """Derive the closed-world cross-domain key registry from public keys."""

    from evoom_guard.signing import public_key_id

    return {
        "trusted_finalizer": public_key_id(args.trusted_finalizer_pub),
        "artifact_admission_v1": public_key_id(args.artifact_admission_v1_pub),
        "artifact_digest_admission_v2": public_key_id(
            args.artifact_digest_admission_v2_pub
        ),
        "release_source_finalizer_v1": public_key_id(
            args.release_source_finalizer_v1_pub
        ),
    }


def _preflight_release_source_admission_paths(args: argparse.Namespace) -> None:
    """Reject destructive aliases and no-clobber failures before provider I/O."""

    def resolved(path: str) -> str:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))

    paths = {
        "output": args.out,
        "source": args.source,
        "context": args.context,
        "producer identity": args.producer,
        "admitter identity": args.admitter,
        "GitHub policy": args.github_policy,
        "producer receipt": args.receipt,
        "handoff": args.handoff,
        "verdict": args.verdict,
        "Git executable": args.git_executable,
        "GitHub CLI executable": args.gh_executable,
        "private key": args.sign_key,
        "public key": args.sign_pub,
        "Trusted Finalizer public key": args.trusted_finalizer_pub,
        "Artifact Admission V1 public key": args.artifact_admission_v1_pub,
        "Artifact Digest Admission V2 public key": (
            args.artifact_digest_admission_v2_pub
        ),
        "Release Source Finalizer V1 public key": (
            args.release_source_finalizer_v1_pub
        ),
        "provider receipt": args.github_receipt_out,
        "provider raw output": args.github_raw_output_out,
    }
    identities: dict[str, str] = {}
    for label, path in paths.items():
        identity = resolved(path)
        if identity in identities:
            raise ValueError(
                f"release-source admission {label} path aliases {identities[identity]}"
            )
        identities[identity] = label
    if os.path.lexists(args.out) and not args.force:
        raise ValueError("release-source admission output already exists and --force was not set")
    for label, path in (
        ("provider receipt", args.github_receipt_out),
        ("provider raw output", args.github_raw_output_out),
    ):
        if os.path.lexists(path):
            raise ValueError(f"{label} output already exists; provider evidence is no-clobber")


def cmd_seal_release_source_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Freshly verify the protected producer relation, then sign one V2 ALLOW."""

    from evoom_guard.admission.release_source import (
        RELEASE_SOURCE_ADMISSION_FORMAT,
        ReleaseSourceAdmissionError,
        seal_release_source_admission,
    )
    from evoom_guard.finalizer_derivation import (
        FinalizerDerivationError,
        git_executable_pin,
    )
    from evoom_guard.github_attestation import (
        GitHubAttestationError,
        github_attestation_provider_isolation,
    )
    from evoom_guard.release_source_producer_receipt import (
        ReleaseSourceProducerReceiptError,
        reverify_attested_release_source_producer_receipt,
        validate_release_source_admitter_runtime_environment,
        verify_release_source_admitter_workflow_blob,
    )
    from evoom_guard.signing import SigningUnavailableError, public_key_id

    return (
        _release_source_admission_command_owner.execute_seal_release_source_admission(
            args,
            services=(
                _release_source_admission_command_owner.SealReleaseSourceAdmissionServices(
                    admission_format=RELEASE_SOURCE_ADMISSION_FORMAT,
                    release_source_error=ReleaseSourceAdmissionError,
                    producer_receipt_error=ReleaseSourceProducerReceiptError,
                    github_error=GitHubAttestationError,
                    finalizer_error=FinalizerDerivationError,
                    signing_unavailable_error=SigningUnavailableError,
                    git_executable_pin=git_executable_pin,
                    provider_isolation=github_attestation_provider_isolation,
                    verify_admitter_workflow=(
                        verify_release_source_admitter_workflow_blob
                    ),
                    validate_admitter_runtime=(
                        validate_release_source_admitter_runtime_environment
                    ),
                    reverify_producer_receipt=(
                        reverify_attested_release_source_producer_receipt
                    ),
                    seal_release_source_admission=seal_release_source_admission,
                    public_key_id=public_key_id,
                    producer_inputs_provider=lambda: (
                        _producer_receipt_external_inputs
                    ),
                    read_external_object_provider=lambda: (
                        _read_external_finalizer_object
                    ),
                    key_separation_provider=lambda: (
                        _release_source_key_separation
                    ),
                    preflight_provider=lambda: (
                        _preflight_release_source_admission_paths
                    ),
                    environment_provider=lambda: os.environ,
                    machine_report_provider=lambda: _machine_report,
                )
            ),
            out=out,
        )
    )


def cmd_verify_release_source_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify a V2 source authorization using only external trust roots."""

    from evoom_guard.admission.release_source import (
        RELEASE_SOURCE_ADMISSION_FORMAT,
        ReleaseSourceAdmissionError,
        verify_release_source_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    return (
        _release_source_admission_command_owner.execute_verify_release_source_admission(
            args,
            services=(
                _release_source_admission_command_owner.VerifyReleaseSourceAdmissionServices(
                    admission_format=RELEASE_SOURCE_ADMISSION_FORMAT,
                    release_source_error=ReleaseSourceAdmissionError,
                    signing_unavailable_error=SigningUnavailableError,
                    verify_release_source_admission=verify_release_source_admission,
                    read_external_object_provider=lambda: (
                        _read_external_finalizer_object
                    ),
                    key_separation_provider=lambda: (
                        _release_source_key_separation
                    ),
                    machine_report_provider=lambda: _machine_report,
                )
            ),
            out=out,
        )
    )


def _release_artifact_key_separation(args: argparse.Namespace) -> dict[str, str]:
    """Derive the exact five-root registry that precedes the RAAE signer."""

    from evoom_guard.signing import public_key_id

    return {
        "trusted_finalizer": public_key_id(args.trusted_finalizer_pub),
        "artifact_admission_v1": public_key_id(args.artifact_admission_v1_pub),
        "artifact_digest_admission_v2": public_key_id(
            args.artifact_digest_admission_v2_pub
        ),
        "release_source_finalizer_v1": public_key_id(
            args.release_source_finalizer_v1_pub
        ),
        "release_source_admission_v2": public_key_id(
            args.release_source_admission_v2_pub
        ),
    }


def _release_artifact_nested_expectations(
    args: argparse.Namespace,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    """Read the externally controlled objects used to re-verify the nested RSAE."""

    source = _read_external_finalizer_object(
        args.expected_release_source,
        label="expected protected-main release source",
    )
    context = _read_external_finalizer_object(
        args.expected_release_source_context,
        label="expected release-source context",
    )
    producer = _read_external_finalizer_object(
        args.expected_release_source_producer,
        label="expected release-source producer",
    )
    admitter = _read_external_finalizer_object(
        args.expected_release_source_admitter,
        label="expected release-source admitter",
    )
    github_policy = _read_external_finalizer_object(
        args.expected_release_source_github_policy,
        label="expected release-source GitHub policy",
    )
    return source, context, producer, admitter, github_policy


def _preflight_release_artifact_admission_paths(
    args: argparse.Namespace,
    *,
    event_path: str,
) -> None:
    """Reject destructive aliases and an existing RAAE before provider access."""

    def resolved(path: str) -> str:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))

    paths = {
        "output": args.out,
        "release-source admission": args.release_source_admission,
        "artifact": args.artifact,
        "builder identity": args.builder,
        "admitter identity": args.admitter,
        "release source": args.expected_release_source,
        "release-source context": args.expected_release_source_context,
        "release-source producer": args.expected_release_source_producer,
        "release-source admitter": args.expected_release_source_admitter,
        "release-source GitHub policy": args.expected_release_source_github_policy,
        "GitHub event payload": event_path,
        "Git executable": args.git_executable,
        "GitHub CLI executable": args.gh_executable,
        "private key": args.sign_key,
        "public key": args.sign_pub,
        "Trusted Finalizer public key": args.trusted_finalizer_pub,
        "Artifact Admission V1 public key": args.artifact_admission_v1_pub,
        "Artifact Digest Admission V2 public key": (
            args.artifact_digest_admission_v2_pub
        ),
        "Release Source Finalizer V1 public key": (
            args.release_source_finalizer_v1_pub
        ),
        "Release Source Admission V2 public key": (
            args.release_source_admission_v2_pub
        ),
    }
    identities: dict[str, str] = {}
    for label, path in paths.items():
        if path == "-":
            raise ValueError(
                f"release-artifact admission {label} must be a regular path, "
                "not standard input/output"
            )
        identity = resolved(path)
        if identity in identities:
            raise ValueError(
                f"release-artifact admission {label} path aliases "
                f"{identities[identity]}"
            )
        identities[identity] = label
    if os.path.lexists(args.out):
        raise ValueError("release-artifact admission output already exists")


def cmd_seal_github_release_artifact_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Bind the live F job to E, freshly verify GitHub, then seal one RAAE."""

    from evoom_guard.admission.release_artifact import (
        RELEASE_ARTIFACT_ADMISSION_FORMAT,
        ReleaseArtifactAdmissionError,
        bind_release_artifact_admitter_runtime,
        seal_release_artifact_admission,
    )
    from evoom_guard.finalizer_derivation import (
        FinalizerDerivationError,
        git_executable_pin,
    )
    from evoom_guard.github_attestation import (
        GitHubAttestationError,
        github_attestation_provider_isolation,
    )
    from evoom_guard.signing import SigningUnavailableError, public_key_id

    return _release_artifact_admission_command_owner.execute_seal_github_release_artifact_admission(
        args,
        services=_release_artifact_admission_command_owner.SealGitHubReleaseArtifactAdmissionServices(
            admission_format=RELEASE_ARTIFACT_ADMISSION_FORMAT,
            release_artifact_error=ReleaseArtifactAdmissionError,
            github_error=GitHubAttestationError,
            finalizer_error=FinalizerDerivationError,
            signing_unavailable_error=SigningUnavailableError,
            bind_runtime_admitter=bind_release_artifact_admitter_runtime,
            seal_release_artifact_admission=seal_release_artifact_admission,
            public_key_id=public_key_id,
            git_executable_pin=git_executable_pin,
            provider_isolation=github_attestation_provider_isolation,
            environment_provider=lambda: os.environ,
            preflight_provider=lambda: _preflight_release_artifact_admission_paths,
            nested_expectations_provider=lambda: (
                _release_artifact_nested_expectations
            ),
            read_external_object_provider=lambda: _read_external_finalizer_object,
            key_separation_provider=lambda: _release_artifact_key_separation,
            machine_report_provider=lambda: _machine_report,
        ),
        out=out,
    )


def cmd_verify_github_release_artifact_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify one RAAE, its artifact, nested RSAE, and all six roots offline."""

    from evoom_guard.admission.release_artifact import (
        RELEASE_ARTIFACT_ADMISSION_FORMAT,
        ReleaseArtifactAdmissionError,
        verify_release_artifact_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    return _release_artifact_admission_command_owner.execute_verify_github_release_artifact_admission(
        args,
        services=_release_artifact_admission_command_owner.VerifyGitHubReleaseArtifactAdmissionServices(
            admission_format=RELEASE_ARTIFACT_ADMISSION_FORMAT,
            release_artifact_error=ReleaseArtifactAdmissionError,
            signing_unavailable_error=SigningUnavailableError,
            verify_release_artifact_admission=verify_release_artifact_admission,
            nested_expectations_provider=lambda: (
                _release_artifact_nested_expectations
            ),
            read_external_object_provider=lambda: _read_external_finalizer_object,
            key_separation_provider=lambda: _release_artifact_key_separation,
            machine_report_provider=lambda: _machine_report,
        ),
        out=out,
    )


def cmd_seal_artifact_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Seal one file only after an external Trusted Finalizer ALLOW."""

    from evoom_guard.artifact_admission import (
        ARTIFACT_BINDING_FORMAT,
        ArtifactAdmissionError,
        seal_artifact_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    return _artifact_admission_command_owner.execute_seal_artifact_admission(
        args,
        services=_artifact_admission_command_owner.SealArtifactAdmissionServices(
            binding_format=ARTIFACT_BINDING_FORMAT,
            artifact_error=ArtifactAdmissionError,
            signing_unavailable_error=SigningUnavailableError,
            seal_artifact_admission=seal_artifact_admission,
            read_external_object_provider=lambda: _read_external_finalizer_object,
            machine_report_provider=lambda: _machine_report,
        ),
        out=out,
    )


def cmd_verify_artifact_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify a file binding with external artifact/finalizer trust inputs."""

    from evoom_guard.artifact_admission import (
        ARTIFACT_BINDING_FORMAT,
        ArtifactAdmissionError,
        verify_artifact_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    return _artifact_admission_command_owner.execute_verify_artifact_admission(
        args,
        services=_artifact_admission_command_owner.VerifyArtifactAdmissionServices(
            binding_format=ARTIFACT_BINDING_FORMAT,
            artifact_error=ArtifactAdmissionError,
            signing_unavailable_error=SigningUnavailableError,
            verify_artifact_admission=verify_artifact_admission,
            read_external_object_provider=lambda: _read_external_finalizer_object,
            machine_report_provider=lambda: _machine_report,
        ),
        out=out,
    )


def cmd_seal_artifact_digest_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Seal one immutable digest after an external Trusted Finalizer ALLOW."""

    from evoom_guard.artifact_digest_admission import (
        ARTIFACT_DIGEST_BINDING_FORMAT,
        ArtifactDigestAdmissionError,
        seal_artifact_digest_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    return _artifact_digest_admission_command_owner.execute_seal_artifact_digest_admission(
        args,
        services=(
            _artifact_digest_admission_command_owner.SealArtifactDigestAdmissionServices(
                binding_format=ARTIFACT_DIGEST_BINDING_FORMAT,
                artifact_error=ArtifactDigestAdmissionError,
                signing_unavailable_error=SigningUnavailableError,
                seal_artifact_digest_admission=seal_artifact_digest_admission,
                read_external_object_provider=lambda: (
                    _read_external_finalizer_object
                ),
                machine_report_provider=lambda: _machine_report,
            )
        ),
        out=out,
    )


def cmd_verify_artifact_digest_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify V2 with external subject, provenance, and finalizer inputs."""

    from evoom_guard.artifact_digest_admission import (
        ARTIFACT_DIGEST_BINDING_FORMAT,
        ArtifactDigestAdmissionError,
        verify_artifact_digest_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    return _artifact_digest_admission_command_owner.execute_verify_artifact_digest_admission(
        args,
        services=(
            _artifact_digest_admission_command_owner.VerifyArtifactDigestAdmissionServices(
                binding_format=ARTIFACT_DIGEST_BINDING_FORMAT,
                artifact_error=ArtifactDigestAdmissionError,
                signing_unavailable_error=SigningUnavailableError,
                verify_artifact_digest_admission=verify_artifact_digest_admission,
                read_external_object_provider=lambda: (
                    _read_external_finalizer_object
                ),
                machine_report_provider=lambda: _machine_report,
            )
        ),
        out=out,
    )


def _github_attestation_policy_kwargs(
    args: argparse.Namespace,
) -> _GitHubAttestationPolicyKwargs:
    """Return only the exact policy inputs accepted by the provider adapter."""

    return {
        "repository": args.repo,
        "signer_workflow": args.signer_workflow,
        "signer_digest": args.signer_digest,
        "source_ref": args.source_ref,
        "source_digest": args.source_digest,
        "cert_oidc_issuer": args.cert_oidc_issuer,
    }


def _github_attestation_provider_isolation(
    args: argparse.Namespace,
) -> GitHubAttestationProviderIsolation | None:
    """Build the optional all-or-nothing POSIX provider-isolation contract."""

    from evoom_guard.github_attestation import (
        GitHubAttestationError,
        github_attestation_provider_isolation,
    )

    digest = args.gh_executable_sha256
    uid = args.provider_isolation_uid
    gid = args.provider_isolation_gid
    supplied = (digest is not None, uid is not None, gid is not None)
    if not any(supplied):
        return None
    if not all(supplied):
        raise GitHubAttestationError(
            "--gh-executable-sha256, --provider-isolation-uid, and "
            "--provider-isolation-gid must be supplied together"
        )
    return github_attestation_provider_isolation(
        args.gh_executable,
        digest,
        uid=uid,
        gid=gid,
    )


def cmd_github_attestation_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Run the narrow provider verifier and retain its exact bounded evidence."""

    from evoom_guard.github_attestation import (
        GITHUB_ATTESTATION_RECEIPT_FORMAT,
        GitHubAttestationError,
        create_github_attestation_receipt,
    )

    return _github_attestation_receipt_command_owner.execute_github_attestation_receipt(
        args,
        services=(
            _github_attestation_receipt_command_owner.CreateGitHubAttestationReceiptServices(
                receipt_format=GITHUB_ATTESTATION_RECEIPT_FORMAT,
                github_error=GitHubAttestationError,
                create_github_attestation_receipt=(
                    create_github_attestation_receipt
                ),
                policy_kwargs_provider=lambda: (
                    _github_attestation_policy_kwargs
                ),
                provider_isolation_provider=lambda: (
                    _github_attestation_provider_isolation
                ),
                machine_report_provider=lambda: _machine_report,
            )
        ),
        out=out,
    )


def cmd_verify_github_attestation_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Check retained evidence continuity without making a live provider call."""

    from evoom_guard.github_attestation import (
        GITHUB_ATTESTATION_RECEIPT_FORMAT,
        GitHubAttestationError,
        verify_github_attestation_receipt,
    )

    return _github_attestation_receipt_command_owner.execute_verify_github_attestation_receipt(
        args,
        services=(
            _github_attestation_receipt_command_owner.VerifyGitHubAttestationReceiptServices(
                receipt_format=GITHUB_ATTESTATION_RECEIPT_FORMAT,
                github_error=GitHubAttestationError,
                verify_github_attestation_receipt=(
                    verify_github_attestation_receipt
                ),
                policy_kwargs_provider=lambda: (
                    _github_attestation_policy_kwargs
                ),
                machine_report_provider=lambda: _machine_report,
            )
        ),
        out=out,
    )


def cmd_reverify_github_attestation_receipt(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Make a fresh constrained GitHub CLI verification for a retained receipt."""

    from evoom_guard.github_attestation import (
        GITHUB_ATTESTATION_RECEIPT_FORMAT,
        GitHubAttestationError,
        reverify_github_attestation_receipt,
    )

    return _github_attestation_receipt_command_owner.execute_reverify_github_attestation_receipt(
        args,
        services=(
            _github_attestation_receipt_command_owner.ReverifyGitHubAttestationReceiptServices(
                receipt_format=GITHUB_ATTESTATION_RECEIPT_FORMAT,
                github_error=GitHubAttestationError,
                reverify_github_attestation_receipt=(
                    reverify_github_attestation_receipt
                ),
                policy_kwargs_provider=lambda: (
                    _github_attestation_policy_kwargs
                ),
                provider_isolation_provider=lambda: (
                    _github_attestation_provider_isolation
                ),
                machine_report_provider=lambda: _machine_report,
            )
        ),
        out=out,
    )


def cmd_seal_github_attestation_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Freshly verify provider evidence, then bind it to a finalizer ALLOW.

    This command intentionally owns no shortcut around the provider policy,
    external finalizer source/context, or separate V2 admission key.  In
    particular it exposes no overwrite switch: a protected job must choose
    fresh, reviewable evidence paths for every run.
    """

    from evoom_guard.artifact_digest_admission import ARTIFACT_DIGEST_BINDING_FORMAT
    from evoom_guard.github_attestation import (
        GitHubAttestationError,
        seal_github_attestation_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    return (
        _github_attestation_admission_command_owner.execute_seal_github_attestation_admission(
            args,
            services=(
                _github_attestation_admission_command_owner.SealGitHubAttestationAdmissionServices(
                    binding_format=ARTIFACT_DIGEST_BINDING_FORMAT,
                    github_error=GitHubAttestationError,
                    signing_unavailable_error=SigningUnavailableError,
                    seal_github_attestation_admission=(
                        seal_github_attestation_admission
                    ),
                    read_external_object_provider=lambda: (
                        _read_external_finalizer_object
                    ),
                    policy_kwargs_provider=lambda: (
                        _github_attestation_policy_kwargs
                    ),
                    provider_isolation_provider=lambda: (
                        _github_attestation_provider_isolation
                    ),
                    machine_report_provider=lambda: _machine_report,
                )
            ),
            out=out,
        )
    )


def cmd_verify_github_attestation_admission(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify retained provider bytes and their V2 finalizer-bound relation."""

    from evoom_guard.artifact_digest_admission import ARTIFACT_DIGEST_BINDING_FORMAT
    from evoom_guard.github_attestation import (
        GitHubAttestationError,
        verify_github_attestation_admission,
    )
    from evoom_guard.signing import SigningUnavailableError

    return (
        _github_attestation_admission_command_owner.execute_verify_github_attestation_admission(
            args,
            services=(
                _github_attestation_admission_command_owner.VerifyGitHubAttestationAdmissionServices(
                    binding_format=ARTIFACT_DIGEST_BINDING_FORMAT,
                    github_error=GitHubAttestationError,
                    signing_unavailable_error=SigningUnavailableError,
                    verify_github_attestation_admission=(
                        verify_github_attestation_admission
                    ),
                    read_external_object_provider=lambda: (
                        _read_external_finalizer_object
                    ),
                    policy_kwargs_provider=lambda: (
                        _github_attestation_policy_kwargs
                    ),
                    machine_report_provider=lambda: _machine_report,
                )
            ),
            out=out,
        )
    )


def cmd_verify_bundle(
    args: argparse.Namespace,
    *,
    out: Callable[[str], None] = print,
) -> int:
    """Verify canonical bytes, external-key authenticity, context, and semantics."""

    from evoom_guard.evidence_bundle import (
        EvidenceBundleError,
        inspect_evidence_bundle,
        verify_bundle_context,
        verify_bundle_signature,
    )
    from evoom_guard.record_verifier import strict_json_loads, verify_record
    from evoom_guard.signing import SigningUnavailableError

    return _record_command_owner.execute_verify_bundle(
        args,
        services=_record_command_owner.VerifyBundleServices(
            read_bounded_bytes=lambda path, *, limit, label: _read_bounded_bytes(
                path,
                limit=limit,
                label=label,
            ),
            strict_json_loads=strict_json_loads,
            verify_record=verify_record,
            inspect_evidence_bundle=inspect_evidence_bundle,
            verify_bundle_signature=verify_bundle_signature,
            verify_bundle_context=verify_bundle_context,
            invalid_bundle_errors=(EvidenceBundleError,),
            signature_operational_errors=(
                OSError,
                ValueError,
                SigningUnavailableError,
            ),
            machine_report=lambda reporter, value: _machine_report(
                reporter,
                value,
            ),
            max_context_bytes=MAX_CONTEXT_INPUT_BYTES,
        ),
        out=out,
    )


def validate_pack(pack_dir: str) -> dict[str, object]:
    """Validate a verifier-pack directory; returns a report dict (see pack-doctor)."""
    return _diagnostic_command_owner.validate_pack(
        pack_dir,
        services=_diagnostic_command_owner.PackValidationServices(
            is_directory=lambda path: os.path.isdir(path),
            test_files=lambda path: pack_test_files(path),
            load_manifest=lambda path: load_pack_manifest(path),
            digest=lambda path: pack_digest(path),
            digest_format=lambda: PACK_DIGEST_FORMAT,
            manifest_error=lambda: PackManifestError,
        ),
    )


def cmd_pack_doctor(args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    """Execute ``evo-guard pack-doctor`` — validate a verifier pack (exit 0/1)."""
    return _diagnostic_command_owner.execute_pack_doctor(
        args,
        report_provider=lambda path: validate_pack(path),
        json_dumps=lambda value, **kwargs: json.dumps(value, **kwargs),
        out=out,
    )


def cmd_version(_args: argparse.Namespace, *, out: Callable[[str], None] = print) -> int:
    return _diagnostic_command_owner.execute_version(
        _args,
        version=lambda: __version__,
        out=out,
    )


def main(argv: list[str] | None = None) -> int:
    """The ``evo-guard`` entry point. Returns a process exit code."""
    _configure_stdio()
    args = build_parser().parse_args(argv)
    if args.command == "guard":
        return cmd_guard(args)
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "finalizer-init":
        return cmd_finalizer_init(args)
    if args.command == "finalizer-doctor":
        return cmd_finalizer_doctor(args)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "keygen":
        return cmd_keygen(args)
    if args.command == "verify-verdict":
        return cmd_verify_verdict(args)
    if args.command == "verify-record":
        return cmd_verify_record(args)
    if args.command == "bundle-evidence":
        return cmd_bundle_evidence(args)
    if args.command == "finalize-record":
        return cmd_finalize_record(args)
    if args.command == "finalizer-handoff":
        return cmd_finalizer_handoff(args)
    if args.command == "derive-finalizer-bindings":
        return cmd_derive_finalizer_bindings(args)
    if args.command == "verify-finalizer-bindings":
        return cmd_verify_finalizer_bindings(args)
    if args.command == "seal-finalizer":
        return cmd_seal_finalizer(args)
    if args.command == "verify-finalized":
        return cmd_verify_finalized(args)
    if args.command == "project-change-attempt-observation":
        return cmd_project_change_attempt_observation(args)
    if args.command == "validate-agent-change-proposal":
        return cmd_validate_agent_change_proposal(args)
    if args.command == "derive-agent-change-bindings":
        return cmd_derive_agent_change_bindings(args)
    if args.command == "seal-agent-change-authorization":
        return cmd_seal_agent_change_authorization(args)
    if args.command == "seal-agent-change-finalized":
        return cmd_seal_agent_change_finalized(args)
    if args.command == "verify-agent-change-finalized":
        return cmd_verify_agent_change_finalized(args)
    if args.command == "release-source-handoff":
        return cmd_release_source_handoff(args)
    if args.command == "seal-release-source-finalizer":
        return cmd_seal_release_source_finalizer(args)
    if args.command == "verify-release-source-finalized":
        return cmd_verify_release_source_finalized(args)
    if args.command == "derive-release-source-controls":
        return cmd_derive_release_source_controls(args)
    if args.command == "create-release-source-producer-receipt":
        return cmd_create_release_source_producer_receipt(args)
    if args.command == "verify-release-source-producer-receipt":
        return cmd_verify_release_source_producer_receipt(args)
    if args.command == "reverify-attested-release-source-producer-receipt":
        return cmd_reverify_attested_release_source_producer_receipt(args)
    if args.command == "seal-release-source-admission":
        return cmd_seal_release_source_admission(args)
    if args.command == "verify-release-source-admission":
        return cmd_verify_release_source_admission(args)
    if args.command == "seal-github-release-artifact-admission":
        return cmd_seal_github_release_artifact_admission(args)
    if args.command == "verify-github-release-artifact-admission":
        return cmd_verify_github_release_artifact_admission(args)
    if args.command == "seal-artifact-admission":
        return cmd_seal_artifact_admission(args)
    if args.command == "verify-artifact-admission":
        return cmd_verify_artifact_admission(args)
    if args.command == "seal-artifact-digest-admission":
        return cmd_seal_artifact_digest_admission(args)
    if args.command == "verify-artifact-digest-admission":
        return cmd_verify_artifact_digest_admission(args)
    if args.command == "github-attestation-receipt":
        return cmd_github_attestation_receipt(args)
    if args.command == "verify-github-attestation-receipt":
        return cmd_verify_github_attestation_receipt(args)
    if args.command == "reverify-github-attestation-receipt":
        return cmd_reverify_github_attestation_receipt(args)
    if args.command == "seal-github-attestation-admission":
        return cmd_seal_github_attestation_admission(args)
    if args.command == "verify-github-attestation-admission":
        return cmd_verify_github_attestation_admission(args)
    if args.command == "verify-bundle":
        return cmd_verify_bundle(args)
    if args.command == "pack-doctor":
        return cmd_pack_doctor(args)
    if args.command == "version":
        return cmd_version(args)
    return 2  # unreachable: subparser is required


if __name__ == "__main__":
    raise SystemExit(main())
