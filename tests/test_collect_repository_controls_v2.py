# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Fail-closed tests for the unsigned repository-control observation collector."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import threading
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from tools.ci import collect_repository_controls_v2 as collector

REPOSITORY = "EvoRiseKsa/EvoOM-Guard-m"
RULESET_ID = 19713401
REPOSITORY_ID = 123456789
REPOSITORY_OWNER_ID = 987654321
FIXED_TIME = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

EXPECTED_NAMES = [
    "main-ref",
    "main-protection",
    "actions-permissions",
    "workflow-permissions",
    "immutable-releases",
    "tag-ruleset",
    "deploy-keys",
    "environments",
    "source-deployment-branch-policies",
    "artifact-deployment-branch-policies",
    "draft-deployment-branch-policies",
    "publication-deployment-branch-policies",
    "activation-variable-1",
    "activation-variable-2",
    "activation-variable-3",
    "post-h-source-environment-secrets",
    "post-h-artifact-environment-secrets",
]


def _json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _link_header(endpoint: str, *, page: int, last: int) -> str | None:
    links: list[str] = []

    def url(target: int) -> str:
        return (
            f"https://api.github.com{endpoint}"
            f"?page={target}&per_page={collector.PER_PAGE}"
        )

    if page > 1:
        links.extend(
            (
                f'<{url(page - 1)}>; rel="prev"',
                f'<{url(1)}>; rel="first"',
            )
        )
    if page < last:
        links.extend(
            (
                f'<{url(page + 1)}>; rel="next"',
                f'<{url(last)}>; rel="last"',
            )
        )
    return ", ".join(links) or None


def _minimal_body(
    endpoint: str,
    query: Mapping[str, int | str],
) -> Any:
    if endpoint.endswith("/git/ref/heads/main"):
        return {
            "ref": "refs/heads/main",
            "object": {"sha": "a" * 40, "type": "commit", "url": "https://example.test"},
        }
    if endpoint.endswith("/branches/main/protection"):
        return {
            "required_status_checks": {"strict": True, "contexts": []},
            "enforce_admins": {"enabled": True},
            "required_pull_request_reviews": {"required_approving_review_count": 1},
            "restrictions": None,
        }
    if endpoint.endswith("/actions/permissions/workflow"):
        return {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        }
    if endpoint.endswith("/actions/permissions"):
        return {"enabled": True, "allowed_actions": "selected"}
    if endpoint.endswith("/immutable-releases"):
        return {"enabled": True, "enforced_by_owner": False}
    if endpoint.endswith(f"/rulesets/{RULESET_ID}"):
        return {
            "id": RULESET_ID,
            "name": "immutable release tags",
            "target": "tag",
            "enforcement": "active",
        }
    if endpoint.endswith("/keys"):
        return []
    if endpoint.endswith("/environments"):
        environments = [
            {"id": index, "name": name}
            for index, (_, name) in enumerate(collector.ENVIRONMENTS, start=1)
        ]
        return {"total_count": len(environments), "environments": environments}
    if endpoint.endswith("/deployment-branch-policies"):
        return {
            "total_count": 1,
            "branch_policies": [
                {
                    "id": sum(endpoint.encode("utf-8")),
                    "name": "main",
                    "type": "branch",
                }
            ],
        }
    if "/actions/variables/" in endpoint:
        return {"name": endpoint.rsplit("/", 1)[1], "value": "false"}
    if endpoint.endswith("/secrets"):
        return {"total_count": 0, "secrets": []}
    raise AssertionError(f"unexpected endpoint: {endpoint}; query={query}")


class FakeRunner:
    def __init__(
        self,
        handler: Callable[
            [str, str, Mapping[str, int | str]], collector.ApiResponse
        ]
        | None = None,
    ) -> None:
        self.calls: list[tuple[str, str, dict[str, int | str]]] = []
        self._handler = handler

    def __call__(
        self,
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        copied_query = dict(query)
        self.calls.append((method, endpoint, copied_query))
        if self._handler is not None:
            return self._handler(method, endpoint, copied_query)
        return collector.ApiResponse(_json(_minimal_body(endpoint, copied_query)))


def _collect(runner: FakeRunner | None = None) -> dict[str, Any]:
    return collector.collect(
        REPOSITORY,
        RULESET_ID,
        repository_id=REPOSITORY_ID,
        repository_owner_id=REPOSITORY_OWNER_ID,
        api_runner=runner or FakeRunner(),
        clock=lambda: FIXED_TIME,
    )


def test_collects_exact_ordered_read_only_observations_and_full_bodies() -> None:
    runner = FakeRunner()

    document = _collect(runner)

    assert set(document) == {
        "collector",
        "evidence_boundary",
        "format",
        "github_api_version",
        "observed_window",
        "observations",
        "repository",
        "repository_id",
        "repository_owner_id",
    }
    assert document["format"] == collector.FORMAT
    assert document["repository_id"] == REPOSITORY_ID
    assert document["repository_owner_id"] == REPOSITORY_OWNER_ID
    assert document["collector"] == {
        "name": "evoguard-release-ledger",
        "version": "2",
    }
    assert document["github_api_version"] == "2022-11-28"
    assert document["observed_window"] == {
        "started_utc": "2030-01-02T03:04:05Z",
        "completed_utc": "2030-01-02T03:04:05Z",
    }
    assert (
        document["evidence_boundary"]
        == "owner-collected-bounded-window-github-api-observation"
    )
    assert [item["name"] for item in document["observations"]] == EXPECTED_NAMES
    assert len(runner.calls) == 17
    assert all(method == "GET" for method, _, _ in runner.calls)
    assert len({endpoint for _, endpoint, _ in runner.calls}) == 17

    for observation, (_, endpoint, query) in zip(
        document["observations"], runner.calls, strict=True
    ):
        assert observation["endpoint"] == endpoint
        assert observation["method"] == "GET"
        assert observation["observed_utc"] == "2030-01-02T03:04:05Z"
        assert observation["pages"][0]["body"] == _minimal_body(endpoint, query)
        assert observation["pages"][0]["http_status"] == 200
        assert observation["pages"][0]["link_header"] is None
        assert observation["pagination"]["complete"] is True
    assert all("claims" not in observation for observation in document["observations"])
    assert "authorization" not in json.dumps(document).lower()


def test_collector_documents_its_non_atomic_trusted_operator_boundaries() -> None:
    documentation = " ".join((collector.__doc__ or "").split())

    for statement in (
        "17 ordered observation definitions/endpoints",
        "do not imply 17 HTTP calls",
        "observed window is non-atomic",
        "validated Link traversal",
        "trusted operator host",
        "not an atomic execution pin",
        "trusted and non-concurrently mutated",
        "not a race-safe writer",
    ):
        assert statement in documentation


def test_paginates_array_and_object_bodies_without_losing_pages() -> None:
    def handler(
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        assert method == "GET"
        if endpoint.endswith("/keys"):
            page = int(query["page"])
            if page == 1:
                body: Any = [{"id": index, "title": f"key-{index}"} for index in range(100)]
            elif page == 2:
                body = [{"id": 100, "title": "key-100"}]
            else:
                raise AssertionError("unexpected deploy-key page")
            return collector.ApiResponse(
                _json(body),
                link_header=_link_header(endpoint, page=page, last=2),
            )
        if endpoint.endswith("/evoguard-release-source-v2/secrets"):
            page = int(query["page"])
            secrets = (
                [{"name": f"SECRET_{index:03d}"} for index in range(100)]
                if page == 1
                else [{"name": "SECRET_100"}]
            )
            return collector.ApiResponse(
                _json({"total_count": 101, "secrets": secrets}),
                link_header=_link_header(endpoint, page=page, last=2),
            )
        return collector.ApiResponse(_json(_minimal_body(endpoint, query)))

    runner = FakeRunner(handler)
    document = _collect(runner)

    assert len(document["observations"]) == 17
    assert len(runner.calls) == 19
    deploy_keys = document["observations"][6]
    assert deploy_keys["pagination"] == {
        "completion_basis": "validated-link-traversal",
        "complete": True,
        "kind": "page-number",
        "link_complete": True,
        "linked_last_page": 2,
        "observed_item_count": 101,
        "page_count": 2,
        "per_page": 100,
        "reported_total_count": None,
        "termination": "link-terminal",
    }
    assert deploy_keys["pages"][0]["body"][99]["id"] == 99
    assert deploy_keys["pages"][1]["body"] == [{"id": 100, "title": "key-100"}]

    source_secrets = document["observations"][15]
    assert source_secrets["pagination"]["page_count"] == 2
    assert source_secrets["pagination"]["reported_total_count"] == 101
    assert (
        source_secrets["pagination"]["termination"]
        == "reported-total-link-terminal"
    )
    assert source_secrets["pages"][1]["body"]["secrets"][0]["name"] == "SECRET_100"


def test_denied_response_fails_without_retaining_error_body() -> None:
    def denied(
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        return collector.ApiResponse(
            _json({"message": "Resource not accessible"}),
            status=403,
        )

    with pytest.raises(collector.CollectionError, match="denied or incomplete"):
        _collect(FakeRunner(denied))


@pytest.mark.parametrize(
    "header_line",
    [
        b"Authorization: Bearer must-not-survive",
        b"Cookie: session=must-not-survive",
        b"Set-Cookie: session=must-not-survive",
    ],
)
def test_included_token_like_headers_are_rejected(header_line: bytes) -> None:
    included = b"HTTP/2.0 200 OK\r\n" + header_line + b"\r\n\r\n{}"

    with pytest.raises(collector.CollectionError, match="sensitive header"):
        collector._parse_included_response(included)


def test_include_parser_keeps_only_status_and_link() -> None:
    link = (
        f"<https://api.github.com/repos/{REPOSITORY}/keys"
        '?page=2&per_page=100>; rel="next"'
    )
    included = (
        b"HTTP/2.0 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"X-RateLimit-Remaining: 4999\r\n"
        + f"Link: {link}\r\n".encode()
        + b"\r\n"
        + b"[]"
    )

    response = collector._parse_included_response(included)

    assert response == collector.ApiResponse(
        body=b"[]",
        status=200,
        link_header=link,
    )


@pytest.mark.parametrize(
    "link",
    [
        (
            f"<https://api.github.com/repos/{REPOSITORY}/keys"
            '?page=3&per_page=100>; rel="next"'
        ),
        (
            f"<https://api.github.com/repos/{REPOSITORY}/environments"
            '?page=2&per_page=100>; rel="next"'
        ),
        (
            f"<https://api.github.com/repos/{REPOSITORY}/keys"
            '?page=2&per_page=100&access_token=secret>; rel="next"'
        ),
        (
            f"<https://evil.example/repos/{REPOSITORY}/keys"
            '?page=2&per_page=100>; rel="next"'
        ),
    ],
)
def test_link_header_cannot_skip_or_escape_the_frozen_endpoint(link: str) -> None:
    with pytest.raises(collector.CollectionError):
        collector._link_relations(
            link,
            endpoint=f"/repos/{REPOSITORY}/keys",
            page_number=1,
            repository_id=REPOSITORY_ID,
        )


def test_link_header_accepts_the_repository_id_canonicalization() -> None:
    endpoint = f"/repos/{REPOSITORY}/keys"
    link = (
        f"<https://api.github.com/repositories/{REPOSITORY_ID}/keys"
        '?page=2&per_page=100>; rel="next", '
        f"<https://api.github.com/repositories/{REPOSITORY_ID}/keys"
        '?page=2&per_page=100>; rel="last"'
    )

    relations, stable_last = collector._link_relations(
        link,
        endpoint=endpoint,
        page_number=1,
        repository_id=REPOSITORY_ID,
    )

    assert relations == {"next", "last"}
    assert stable_last == 2


def test_link_header_rejects_duplicate_relations() -> None:
    endpoint = f"/repos/{REPOSITORY}/keys"
    next_link = (
        f"<https://api.github.com{endpoint}"
        '?page=2&per_page=100>; rel="next"'
    )

    with pytest.raises(collector.CollectionError, match="duplicate relation"):
        collector._link_relations(
            f"{next_link}, {next_link}",
            endpoint=endpoint,
            page_number=1,
            repository_id=REPOSITORY_ID,
        )


def test_link_header_last_page_is_stable_across_requests() -> None:
    endpoint = f"/repos/{REPOSITORY}/keys"
    first = (
        f"<https://api.github.com{endpoint}?page=2&per_page=100>; rel=\"next\", "
        f"<https://api.github.com{endpoint}?page=3&per_page=100>; rel=\"last\""
    )
    _, stable_last = collector._link_relations(
        first,
        endpoint=endpoint,
        page_number=1,
        repository_id=REPOSITORY_ID,
    )
    changed = (
        f"<https://api.github.com{endpoint}?page=3&per_page=100>; rel=\"next\", "
        f"<https://api.github.com{endpoint}?page=4&per_page=100>; rel=\"last\""
    )

    with pytest.raises(collector.CollectionError, match="changed during pagination"):
        collector._link_relations(
            changed,
            endpoint=endpoint,
            page_number=2,
            repository_id=REPOSITORY_ID,
            expected_last_page=stable_last,
        )


@pytest.mark.parametrize(
    ("page_number", "link", "message"),
    [
        (
            1,
            (
                f"<https://api.github.com/repos/{REPOSITORY}/keys"
                '?page=2&per_page=100>; rel="next"'
            ),
            "no last-page bound",
        ),
        (
            2,
            (
                f"<https://api.github.com/repos/{REPOSITORY}/keys"
                '?page=3&per_page=100>; rel="next", '
                f"<https://api.github.com/repos/{REPOSITORY}/keys"
                '?page=2&per_page=100>; rel="last"'
            ),
            "precedes its next",
        ),
        (
            2,
            (
                f"<https://api.github.com/repos/{REPOSITORY}/keys"
                '?page=3&per_page=100>; rel="last"'
            ),
            "not the current page",
        ),
    ],
)
def test_link_header_enforces_next_and_terminal_last_bounds(
    page_number: int,
    link: str,
    message: str,
) -> None:
    with pytest.raises(collector.CollectionError, match=message):
        collector._link_relations(
            link,
            endpoint=f"/repos/{REPOSITORY}/keys",
            page_number=page_number,
            repository_id=REPOSITORY_ID,
        )


def test_non_paginated_endpoint_rejects_a_link_header() -> None:
    def linked(
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        body = _minimal_body(endpoint, query)
        return collector.ApiResponse(
            _json(body),
            link_header=_link_header(endpoint, page=1, last=2),
        )

    with pytest.raises(collector.CollectionError, match="non-paginated"):
        _collect(FakeRunner(linked))


def test_paginated_link_cannot_continue_beyond_reported_total() -> None:
    def contradictory(
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        body = _minimal_body(endpoint, query)
        if endpoint.endswith("/environments"):
            return collector.ApiResponse(
                _json(body),
                link_header=_link_header(endpoint, page=1, last=2),
            )
        return collector.ApiResponse(_json(body))

    with pytest.raises(collector.CollectionError, match="beyond its reported total"):
        _collect(FakeRunner(contradictory))


def test_header_material_inside_a_body_is_rejected() -> None:
    def smuggled(
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        return collector.ApiResponse(
            _json({"headers": {"Authorization": "Bearer must-not-survive"}})
        )

    with pytest.raises(collector.CollectionError, match="HTTP-header material"):
        _collect(FakeRunner(smuggled))


def test_oversized_response_fails_before_document_creation() -> None:
    def oversized(
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        return collector.ApiResponse(
            _json({"padding": "x" * collector.MAX_API_PAGE_BYTES})
        )

    with pytest.raises(collector.CollectionError, match="one-MiB response bound"):
        _collect(FakeRunner(oversized))


def test_cumulative_canonical_output_is_bounded() -> None:
    padding = "x" * 70000

    def large_pages(
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        body = _minimal_body(endpoint, query)
        if isinstance(body, dict):
            body["padding"] = padding
        return collector.ApiResponse(_json(body))

    with pytest.raises(collector.CollectionError, match="exceeds one MiB"):
        _collect(FakeRunner(large_pages))


def test_existing_output_is_never_overwritten(tmp_path: Path) -> None:
    output = tmp_path / "observation.json"
    output.write_bytes(b"owner bytes\n")

    with pytest.raises(collector.CollectionError, match="overwrite"):
        collector.write_new_output(output, b"replacement\n")

    assert output.read_bytes() == b"owner bytes\n"


def test_link_like_output_parent_is_refused_when_supported(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    link_parent = tmp_path / "linked"
    real_parent.mkdir()
    try:
        os.symlink(real_parent, link_parent, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable to this user")

    with pytest.raises(collector.CollectionError, match="link-like path"):
        collector.write_new_output(link_parent / "observation.json", b"{}\n")


def test_output_is_exact_deterministic_canonical_json(tmp_path: Path) -> None:
    first = _collect()
    second = _collect()

    first_bytes = collector.canonical_json_bytes(first)
    second_bytes = collector.canonical_json_bytes(second)
    assert first_bytes == second_bytes
    assert first_bytes.endswith(b"\n")
    assert b"\n" not in first_bytes[:-1]
    assert b": " not in first_bytes
    assert first_bytes == (
        json.dumps(
            first,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")

    output = tmp_path / "observation.json"
    collector.write_new_output(output, first_bytes)
    assert output.read_bytes() == first_bytes


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            b'{"ref":"refs/heads/main","ref":"refs/heads/other"}',
            "duplicate JSON key",
        ),
        (b'{"value":NaN}', "non-finite JSON constant"),
        (b'{"value":"\\ud800"}', "Unicode surrogate"),
    ],
)
def test_noncanonical_json_responses_fail(body: bytes, message: str) -> None:
    def invalid(
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        return collector.ApiResponse(body)

    with pytest.raises(collector.CollectionError, match=message):
        _collect(FakeRunner(invalid))


def test_incomplete_reported_pagination_fails_closed() -> None:
    def incomplete(
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        if endpoint.endswith("/environments"):
            return collector.ApiResponse(
                _json(
                    {
                        "total_count": 2,
                        "environments": [{"id": 1, "name": "only-one"}],
                    }
                )
            )
        return collector.ApiResponse(_json(_minimal_body(endpoint, query)))

    with pytest.raises(collector.CollectionError, match="ended before its reported total"):
        _collect(FakeRunner(incomplete))


def test_duplicate_paginated_identity_fails_closed() -> None:
    def duplicate(
        method: str,
        endpoint: str,
        query: Mapping[str, int | str],
    ) -> collector.ApiResponse:
        if endpoint.endswith("/keys"):
            if query["page"] == 1:
                return collector.ApiResponse(
                    _json([{"id": index} for index in range(100)]),
                    link_header=_link_header(endpoint, page=1, last=2),
                )
            return collector.ApiResponse(_json([{"id": 99}]))
        return collector.ApiResponse(_json(_minimal_body(endpoint, query)))

    with pytest.raises(collector.CollectionError, match="duplicate paginated item"):
        _collect(FakeRunner(duplicate))


@pytest.mark.parametrize(
    ("repository", "ruleset"),
    [
        (" EvoRiseKsa/EvoOM-Guard-m", RULESET_ID),
        ("EvoRiseKsa/EvoOM-Guard-m.git", RULESET_ID),
        ("EvoRiseKsa//EvoOM-Guard-m", RULESET_ID),
        (REPOSITORY, 0),
        (REPOSITORY, True),
    ],
)
def test_noncanonical_cli_identities_fail(
    repository: str,
    ruleset: int,
) -> None:
    with pytest.raises(collector.CollectionError):
        collector.collect(
            repository,
            ruleset,
            repository_id=REPOSITORY_ID,
            repository_owner_id=REPOSITORY_OWNER_ID,
            api_runner=FakeRunner(),
            clock=lambda: FIXED_TIME,
        )


@pytest.mark.parametrize(
    ("repository_id", "repository_owner_id"),
    [
        (0, REPOSITORY_OWNER_ID),
        (True, REPOSITORY_OWNER_ID),
        (REPOSITORY_ID, 0),
        (REPOSITORY_ID, True),
        (2**63, REPOSITORY_OWNER_ID),
        (REPOSITORY_ID, 2**63),
    ],
)
def test_reviewed_repository_numeric_identities_are_canonical(
    repository_id: int,
    repository_owner_id: int,
) -> None:
    with pytest.raises(collector.CollectionError, match="ID"):
        collector.collect(
            REPOSITORY,
            RULESET_ID,
            repository_id=repository_id,
            repository_owner_id=repository_owner_id,
            api_runner=FakeRunner(),
            clock=lambda: FIXED_TIME,
        )


def test_observation_timestamps_must_remain_inside_completed_window() -> None:
    earlier = datetime(2029, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    times = iter([FIXED_TIME] * 18 + [earlier])

    with pytest.raises(collector.CollectionError, match="moved backwards"):
        collector.collect(
            REPOSITORY,
            RULESET_ID,
            repository_id=REPOSITORY_ID,
            repository_owner_id=REPOSITORY_OWNER_ID,
            api_runner=FakeRunner(),
            clock=lambda: next(times),
        )


def test_gh_runner_uses_absolute_pinned_binary_and_keeps_token_out_of_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable_path = (tmp_path / ("gh.exe" if os.name == "nt" else "gh")).absolute()
    executable_path.write_bytes(b"fixed gh bytes")
    executable_path.chmod(executable_path.stat().st_mode | stat.S_IXUSR)
    executable = collector._snapshot_gh_executable(executable_path)
    included = b"HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    captured: dict[str, Any] = {}

    class Stdout:
        def read(self, limit: int) -> bytes:
            assert limit == collector.MAX_INCLUDED_RESPONSE_BYTES + 1
            return included

    class Process:
        stdout = Stdout()

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            raise AssertionError("bounded successful process must not be killed")

    def popen(command: list[str], **kwargs: Any) -> Process:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Process()

    monkeypatch.setattr(collector, "_resolve_gh_executable", lambda: executable)
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setenv("GH_TOKEN", "must-not-appear-in-argv")
    monkeypatch.setenv("GH_DEBUG", "api")

    response = collector._run_gh_api("GET", "/repos/o/r/example", {})

    command = captured["command"]
    kwargs = captured["kwargs"]
    assert response == collector.ApiResponse(body=b"{}", status=200)
    assert command[0] == str(executable_path)
    assert Path(command[0]).is_absolute()
    assert "--include" in command
    assert "--hostname" in command
    assert "Accept: application/vnd.github+json" in command
    assert "must-not-appear-in-argv" not in repr(command)
    assert kwargs["cwd"] == executable_path.parent
    assert kwargs["env"]["GH_TOKEN"] == "must-not-appear-in-argv"
    assert "GH_DEBUG" not in kwargs["env"]
    assert kwargs["stderr"] is subprocess.DEVNULL
    if os.name == "nt":
        assert kwargs["creationflags"] == subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        assert kwargs["start_new_session"] is True


def test_gh_runner_timeout_cleans_the_process_tree_and_unblocks_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable_path = (tmp_path / ("gh.exe" if os.name == "nt" else "gh")).absolute()
    executable_path.write_bytes(b"fixed timeout gh bytes")
    executable_path.chmod(executable_path.stat().st_mode | stat.S_IXUSR)
    executable = collector._snapshot_gh_executable(executable_path)
    released = threading.Event()
    cleaned: list[Any] = []

    class Stdout:
        def read(self, limit: int) -> bytes:
            released.wait(5)
            return b""

    class Process:
        stdout = Stdout()
        pid = 12345

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            released.set()

    process = Process()

    def cleanup(value: Any) -> None:
        cleaned.append(value)
        released.set()

    monkeypatch.setattr(collector, "_resolve_gh_executable", lambda: executable)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(collector, "_terminate_process_tree", cleanup)
    monkeypatch.setattr(collector, "GH_API_TIMEOUT_SECONDS", 0.02)

    with pytest.raises(collector.CollectionError, match="bounded timeout"):
        collector._run_gh_api("GET", "/repos/o/r/example", {})

    assert cleaned == [process]


def test_gh_runner_oversized_stdout_cleans_the_process_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable_path = (tmp_path / ("gh.exe" if os.name == "nt" else "gh")).absolute()
    executable_path.write_bytes(b"fixed oversize gh bytes")
    executable_path.chmod(executable_path.stat().st_mode | stat.S_IXUSR)
    executable = collector._snapshot_gh_executable(executable_path)
    cleaned: list[Any] = []

    class Stdout:
        def read(self, limit: int) -> bytes:
            return b"x" * limit

    class Process:
        stdout = Stdout()
        pid = 12346

        def wait(self, timeout: float | None = None) -> int:
            raise AssertionError("oversized stdout must be cleaned before wait")

        def kill(self) -> None:
            pass

    process = Process()
    monkeypatch.setattr(collector, "_resolve_gh_executable", lambda: executable)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        collector,
        "_terminate_process_tree",
        lambda value: cleaned.append(value),
    )

    with pytest.raises(collector.CollectionError, match="total byte bound"):
        collector._run_gh_api("GET", "/repos/o/r/example", {})

    assert cleaned == [process]


def test_gh_resolution_accepts_only_safe_absolute_path_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    executable_path = trusted / ("gh.exe" if os.name == "nt" else "gh")
    executable_path.write_bytes(b"bounded executable")
    executable_path.chmod(executable_path.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(trusted.absolute()))

    resolved = collector._resolve_gh_executable()

    assert resolved.path == executable_path.absolute()
    assert resolved.sha256


def test_gh_resolution_accepts_a_regular_hardlinked_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_directory = tmp_path / "source"
    trusted = tmp_path / "trusted"
    source_directory.mkdir()
    trusted.mkdir()
    source = source_directory / "gh-source"
    executable_path = trusted / ("gh.exe" if os.name == "nt" else "gh")
    source.write_bytes(b"hardlinked bounded executable")
    source.chmod(source.stat().st_mode | stat.S_IXUSR)
    try:
        os.link(source, executable_path)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    executable_path.chmod(executable_path.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(trusted.absolute()))

    resolved = collector._resolve_gh_executable()

    assert resolved.path == executable_path.absolute()
    assert resolved.identity[-1] == 2


def test_gh_resolution_rejects_relative_path_and_current_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable_path = tmp_path / ("gh.exe" if os.name == "nt" else "gh")
    executable_path.write_bytes(b"untrusted current-directory executable")
    executable_path.chmod(executable_path.stat().st_mode | stat.S_IXUSR)
    monkeypatch.chdir(tmp_path)

    monkeypatch.setenv("PATH", ".")
    with pytest.raises(collector.CollectionError, match="no safe absolute"):
        collector._resolve_gh_executable()

    monkeypatch.setenv("PATH", str(tmp_path.absolute()))
    with pytest.raises(collector.CollectionError, match="no safe absolute"):
        collector._resolve_gh_executable()


@pytest.mark.parametrize("path_relation", ["ancestor", "descendant"])
def test_gh_resolution_rejects_path_directories_overlapping_cwd_both_ways(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path_relation: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    if path_relation == "ancestor":
        path_directory = tmp_path
        monkeypatch.chdir(workspace)
    else:
        path_directory = workspace / "bin"
        path_directory.mkdir()
        monkeypatch.chdir(workspace)
    executable_path = path_directory / ("gh.exe" if os.name == "nt" else "gh")
    executable_path.write_bytes(b"overlapping executable")
    executable_path.chmod(executable_path.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(path_directory.absolute()))

    with pytest.raises(collector.CollectionError, match="no safe absolute"):
        collector._resolve_gh_executable()


def test_gh_runner_detects_executable_byte_mutation_during_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable_path = (tmp_path / ("gh.exe" if os.name == "nt" else "gh")).absolute()
    executable_path.write_bytes(b"before")
    executable_path.chmod(executable_path.stat().st_mode | stat.S_IXUSR)
    executable = collector._snapshot_gh_executable(executable_path)
    included = b"HTTP/2.0 200 OK\r\n\r\n{}"

    class Stdout:
        def read(self, limit: int) -> bytes:
            return included

    class Process:
        stdout = Stdout()

        def wait(self, timeout: float | None = None) -> int:
            executable_path.write_bytes(b"after")
            return 0

        def kill(self) -> None:
            raise AssertionError("process must not be killed")

    monkeypatch.setattr(collector, "_resolve_gh_executable", lambda: executable)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())

    with pytest.raises(collector.CollectionError, match="identity or bytes changed"):
        collector._run_gh_api("GET", "/repos/o/r/example", {})
