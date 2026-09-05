"""Regression tests for the exact extended-runner Maven cache inventory."""

from __future__ import annotations

import hashlib
import http.client
import io
import os
import stat
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

import tools.conformance.fetch_live_runner_maven_cache as maven_fetch
import tools.conformance.verify_live_runner_maven_cache as maven_verify
from tools.conformance.fetch_live_runner_maven_cache import (
    MAVEN_CENTRAL_ORIGIN,
    MavenFetchError,
    fetch_cache,
)
from tools.conformance.verify_live_runner_maven_cache import (
    MavenCacheError,
    load_manifest,
    verify_cache,
)


class _Response:
    def __init__(
        self,
        payload: bytes,
        url: str,
        *,
        final_url: str | None = None,
        headers: dict[str, str | None] | None = None,
    ) -> None:
        self._body = io.BytesIO(payload)
        self._url = final_url or url
        self.status = 200
        self.headers = {"Content-Length": str(len(payload))}
        for name, value in (headers or {}).items():
            if value is None:
                self.headers.pop(name, None)
            else:
                self.headers[name] = value

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self, size: int) -> bytes:
        return self._body.read(size)


class _Opener:
    def __init__(
        self,
        payloads: dict[str, bytes],
        *,
        final_url: str | None = None,
        headers: dict[str, str | None] | None = None,
    ) -> None:
        self.payloads = payloads
        self.final_url = final_url
        self.headers = headers
        self.calls: list[tuple[str, int]] = []

    def open(self, request: urllib.request.Request, *, timeout: int) -> _Response:
        url = request.full_url
        self.calls.append((url, timeout))
        return _Response(
            self.payloads[url],
            url,
            final_url=self.final_url,
            headers=self.headers,
        )


class _ReadFailureResponse(_Response):
    def __init__(self, payload: bytes, url: str) -> None:
        super().__init__(payload, url)
        self._reads = 0

    def read(self, size: int) -> bytes:
        self._reads += 1
        if self._reads == 1:
            return super().read(min(size, 1))
        raise OSError("simulated interrupted response")


class _AlwaysFailingOpener:
    def __init__(self, payload: bytes, repository: Path) -> None:
        self.payload = payload
        self.repository = repository
        self.calls = 0

    def open(self, request: urllib.request.Request, *, timeout: int) -> _Response:
        del timeout
        if self.calls:
            assert not list(self.repository.rglob("*.part"))
        self.calls += 1
        return _ReadFailureResponse(self.payload, request.full_url)


class _OpenFailureOpener:
    def __init__(self) -> None:
        self.calls = 0

    def open(self, request: urllib.request.Request, *, timeout: int) -> _Response:
        del request, timeout
        self.calls += 1
        raise http.client.RemoteDisconnected("simulated open failure")


def _write_manifest(manifest: Path, payloads: dict[str, bytes]) -> None:
    rows = [
        f"{hashlib.sha256(payload).hexdigest()}  {relative}"
        for relative, payload in sorted(payloads.items())
    ]
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")


def _write_inventory(repository: Path, manifest: Path) -> None:
    rows = []
    for relative in ("example/a/1/a-1.jar", "example/a/1/a-1.pom"):
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = relative.encode("utf-8")
        path.write_bytes(payload)
        rows.append(f"{hashlib.sha256(payload).hexdigest()}  {relative}")
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")


def test_verify_cache_requires_exact_set_and_bytes(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    manifest = tmp_path / "artifacts.sha256"
    _write_inventory(repository, manifest)

    count, digest = verify_cache(repository, manifest)

    assert count == 2
    assert digest == hashlib.sha256(manifest.read_bytes()).hexdigest()
    (repository / "example/a/1/a-1.jar").write_bytes(b"changed")
    with pytest.raises(MavenCacheError, match="digest differs"):
        verify_cache(repository, manifest)


def test_fetch_cache_uses_only_fixed_maven_central_and_verifies_bytes(
    tmp_path: Path,
) -> None:
    payloads = {
        "example/a/1/a-1.jar": b"reviewed jar",
        "example/a/1/a-1.pom": b"reviewed pom",
    }
    manifest = tmp_path / "artifacts.sha256"
    _write_manifest(manifest, payloads)
    repository = tmp_path / "repository"
    remote = {
        f"{MAVEN_CENTRAL_ORIGIN}/maven2/{relative}": payload
        for relative, payload in payloads.items()
    }
    opener = _Opener(remote)

    count, manifest_digest = fetch_cache(
        repository,
        manifest,
        _opener=opener,
        _attempts=1,
    )

    assert count == 2
    assert manifest_digest == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert [url for url, _timeout in opener.calls] == sorted(remote)
    assert all(timeout == 30 for _url, timeout in opener.calls)
    assert (repository / "example/a/1/a-1.jar").read_bytes() == b"reviewed jar"
    assert not list(repository.rglob("*.part"))


def test_fetch_cache_rejects_redirect_digest_drift_and_existing_destination(
    tmp_path: Path,
) -> None:
    relative = "example/a/1/a-1.jar"
    manifest = tmp_path / "artifacts.sha256"
    _write_manifest(manifest, {relative: b"reviewed"})
    url = f"{MAVEN_CENTRAL_ORIGIN}/maven2/{relative}"

    with pytest.raises(MavenFetchError, match="origin or path changed"):
        fetch_cache(
            tmp_path / "redirected",
            manifest,
            _opener=_Opener({url: b"reviewed"}, final_url="https://example.test/a.jar"),
            _attempts=1,
        )

    with pytest.raises(MavenFetchError, match="digest differs"):
        fetch_cache(
            tmp_path / "changed",
            manifest,
            _opener=_Opener({url: b"changed"}),
            _attempts=1,
        )

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(MavenFetchError, match="must not already exist"):
        fetch_cache(existing, manifest, _opener=_Opener({url: b"reviewed"}))


def test_fetch_cache_rejects_encoded_and_invalid_length_responses(
    tmp_path: Path,
) -> None:
    relative = "example/a/1/a-1.jar"
    payload = b"reviewed"
    manifest = tmp_path / "artifacts.sha256"
    _write_manifest(manifest, {relative: payload})
    url = f"{MAVEN_CENTRAL_ORIGIN}/maven2/{relative}"

    with pytest.raises(MavenFetchError, match="encoded .* forbidden"):
        fetch_cache(
            tmp_path / "encoded",
            manifest,
            _opener=_Opener(
                {url: payload}, headers={"Content-Encoding": "gzip"}
            ),
            _attempts=1,
        )
    with pytest.raises(MavenFetchError, match="Content-Length is invalid"):
        fetch_cache(
            tmp_path / "invalid-length",
            manifest,
            _opener=_Opener({url: payload}, headers={"Content-Length": "-1"}),
            _attempts=1,
        )


def test_fetch_cache_rejects_declared_and_streamed_artifact_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = "example/a/1/a-1.jar"
    payload = b"12345"
    manifest = tmp_path / "artifacts.sha256"
    _write_manifest(manifest, {relative: payload})
    url = f"{MAVEN_CENTRAL_ORIGIN}/maven2/{relative}"
    monkeypatch.setattr(maven_fetch, "MAX_ARTIFACT_BYTES", 4)

    with pytest.raises(MavenFetchError, match="exceeds its byte limit"):
        fetch_cache(
            tmp_path / "declared-overflow",
            manifest,
            _opener=_Opener({url: payload}),
            _attempts=1,
        )
    with pytest.raises(MavenFetchError, match="exceeds its byte limit"):
        fetch_cache(
            tmp_path / "streamed-overflow",
            manifest,
            _opener=_Opener({url: payload}, headers={"Content-Length": None}),
            _attempts=1,
        )


def test_fetch_cache_bounds_retries_and_cleans_partial_files(tmp_path: Path) -> None:
    relative = "example/a/1/a-1.jar"
    payload = b"reviewed"
    manifest = tmp_path / "artifacts.sha256"
    _write_manifest(manifest, {relative: payload})
    repository = tmp_path / "repository"
    opener = _AlwaysFailingOpener(payload, repository)
    sleeps: list[float] = []

    with pytest.raises(MavenFetchError, match="response failed"):
        fetch_cache(
            repository,
            manifest,
            _opener=opener,
            _attempts=2,
            _sleep=sleeps.append,
        )

    assert opener.calls == 2
    assert sleeps == [1.0]
    assert not list(repository.rglob("*.part"))
    assert not (repository / relative).exists()


def test_fetch_cache_bounds_open_transport_retries(tmp_path: Path) -> None:
    relative = "example/a/1/a-1.jar"
    payload = b"reviewed"
    manifest = tmp_path / "artifacts.sha256"
    _write_manifest(manifest, {relative: payload})
    opener = _OpenFailureOpener()
    sleeps: list[float] = []

    with pytest.raises(MavenFetchError, match="transport failed"):
        fetch_cache(
            tmp_path / "repository",
            manifest,
            _opener=opener,
            _attempts=2,
            _sleep=sleeps.append,
        )

    assert opener.calls == 2
    assert sleeps == [1.0]


def test_fetch_cache_rejects_exhausted_aggregate_before_network_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = "example/a/1/a-1.jar"
    payload = b"reviewed"
    manifest = tmp_path / "artifacts.sha256"
    _write_manifest(manifest, {relative: payload})
    url = f"{MAVEN_CENTRAL_ORIGIN}/maven2/{relative}"
    opener = _Opener({url: payload})
    monkeypatch.setattr(maven_fetch, "_MAX_REPOSITORY_BYTES", 0)

    with pytest.raises(MavenFetchError, match="aggregate byte limit"):
        fetch_cache(repository=tmp_path / "repository", manifest=manifest, _opener=opener)

    assert opener.calls == []


def test_verify_cache_rejects_missing_extra_and_noncanonical_manifest(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    manifest = tmp_path / "artifacts.sha256"
    _write_inventory(repository, manifest)
    (repository / "extra.jar").write_bytes(b"extra")
    with pytest.raises(MavenCacheError, match="inventory differs"):
        verify_cache(repository, manifest)

    manifest.write_bytes(manifest.read_bytes().replace(b"\n", b"\r\n"))
    with pytest.raises(MavenCacheError, match="canonical LF"):
        load_manifest(manifest)


def test_manifest_rejects_traversal_and_duplicate_paths(tmp_path: Path) -> None:
    manifest = tmp_path / "artifacts.sha256"
    digest = "0" * 64
    manifest.write_text(
        f"{digest}  ../escape.jar\n", encoding="utf-8", newline="\n"
    )
    with pytest.raises(MavenCacheError, match="unsafe"):
        load_manifest(manifest)

    manifest.write_text(
        f"{digest}  a/x.jar\n{digest}  a/x.jar\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(MavenCacheError, match="duplicate"):
        load_manifest(manifest)


@pytest.mark.parametrize(
    "relative",
    ("/escape.jar", "//host/share.jar", "a//b.jar", "a/./b.jar"),
)
def test_manifest_rejects_absolute_and_noncanonical_paths(
    tmp_path: Path,
    relative: str,
) -> None:
    manifest = tmp_path / "artifacts.sha256"
    manifest.write_text(
        f"{'0' * 64}  {relative}\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(MavenCacheError, match="unsafe"):
        load_manifest(manifest)


def test_verify_cache_rejects_a_symlinked_repository_root(tmp_path: Path) -> None:
    real_repository = tmp_path / "real"
    real_repository.mkdir()
    manifest = tmp_path / "artifacts.sha256"
    _write_inventory(real_repository, manifest)
    linked_repository = tmp_path / "linked"
    try:
        linked_repository.symlink_to(real_repository, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    with pytest.raises(MavenCacheError, match="real directory"):
        verify_cache(linked_repository, manifest)


def test_verify_cache_rejects_a_nested_windows_reparse_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    nested = repository / "nested"
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0) or 0x400
    fake_reparse = SimpleNamespace(
        st_mode=stat.S_IFDIR,
        st_file_attributes=marker,
    )
    real_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result:
        if path == nested:
            return fake_reparse  # type: ignore[return-value]
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(
        maven_verify.os,
        "walk",
        lambda *_args, **_kwargs: iter(((str(repository.resolve()), ["nested"], []),)),
    )

    with pytest.raises(MavenCacheError, match="symlinked directory"):
        maven_verify._artifact_paths(repository)


def test_verify_cache_uses_one_stable_manifest_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    manifest = tmp_path / "artifacts.sha256"
    _write_inventory(repository, manifest)
    real_read = maven_verify.read_stable_regular_file
    manifest_reads = 0

    def tracked_read(path: Path, *, label: str, max_bytes: int) -> bytes:
        nonlocal manifest_reads
        if path == manifest:
            manifest_reads += 1
        return real_read(path, label=label, max_bytes=max_bytes)

    monkeypatch.setattr(maven_verify, "read_stable_regular_file", tracked_read)

    verify_cache(repository, manifest)

    assert manifest_reads == 1
