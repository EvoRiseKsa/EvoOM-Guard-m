"""Fetch the reviewed Maven cache without executing Maven or downloaded code."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from tools.conformance.secure_io import ConformanceIOError
from tools.conformance.verify_live_runner_maven_cache import (
    DEFAULT_MANIFEST,
    MAX_ARTIFACT_BYTES,
    MavenCacheError,
    load_manifest,
    verify_cache,
)

MAVEN_CENTRAL_ORIGIN = "https://repo.maven.apache.org"
_MAVEN_CENTRAL_PREFIX = "/maven2/"
_FETCH_CHUNK_BYTES = 64 * 1024
_MAX_REPOSITORY_BYTES = 512 * 1024 * 1024
_FETCH_ATTEMPTS = 3
_FETCH_TIMEOUT_SECONDS = 30


class MavenFetchError(ValueError):
    """The reviewed Maven cache could not be fetched without ambiguity."""


class _RetryableMavenFetchError(MavenFetchError):
    """A bounded retry may recover this transport failure."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        raise MavenFetchError("Maven Central redirects are forbidden")


def _default_opener() -> urllib.request.OpenerDirector:
    """Use direct, certificate-verified HTTPS and refuse proxy/redirect drift."""

    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _RejectRedirects(),
    )


def _artifact_url(relative: str) -> str:
    encoded = urllib.parse.quote(relative, safe="/")
    return MAVEN_CENTRAL_ORIGIN + _MAVEN_CENTRAL_PREFIX + encoded


def _content_length(headers: Any) -> int | None:
    raw = headers.get("Content-Length")
    if raw is None:
        return None
    if not raw.isascii() or not raw.isdecimal():
        raise MavenFetchError("Maven artifact Content-Length is invalid")
    return int(raw)


def _download_once(
    *,
    opener: Any,
    url: str,
    destination: Path,
    expected_digest: str,
    remaining_bytes: int,
) -> int:
    if remaining_bytes <= 0:
        raise MavenFetchError("Maven repository exceeds its aggregate byte limit")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "EvoOM-Guard-m-live-runner-maven-fetch/1",
        },
        method="GET",
    )
    try:
        response = opener.open(request, timeout=_FETCH_TIMEOUT_SECONDS)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        if code == 429 or 500 <= code <= 599:
            raise _RetryableMavenFetchError(
                f"Maven Central returned retryable HTTP {code}"
            ) from exc
        raise MavenFetchError(f"Maven Central returned HTTP {code}") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise _RetryableMavenFetchError(
            f"Maven Central transport failed: {exc}"
        ) from exc

    partial = destination.with_name(destination.name + ".part")
    created = False
    try:
        with response:
            if getattr(response, "status", None) != 200:
                raise MavenFetchError("Maven Central response status is not 200")
            if response.geturl() != url:
                raise MavenFetchError("Maven Central response origin or path changed")
            encoding = response.headers.get("Content-Encoding")
            if encoding not in {None, "identity"}:
                raise MavenFetchError("encoded Maven artifact responses are forbidden")
            declared_length = _content_length(response.headers)
            byte_limit = min(MAX_ARTIFACT_BYTES, remaining_bytes)
            if declared_length is not None and declared_length > byte_limit:
                raise MavenFetchError("Maven artifact exceeds its byte limit")

            destination.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(partial, flags, 0o600)
            created = True
            digest = hashlib.sha256()
            total = 0
            with os.fdopen(descriptor, "wb") as stream:
                while True:
                    try:
                        chunk = response.read(
                            min(_FETCH_CHUNK_BYTES, byte_limit + 1 - total)
                        )
                    except (OSError, http.client.HTTPException) as exc:
                        raise _RetryableMavenFetchError(
                            f"Maven Central response failed: {exc}"
                        ) from exc
                    if not chunk:
                        break
                    stream.write(chunk)
                    digest.update(chunk)
                    total += len(chunk)
                    if total > byte_limit:
                        raise MavenFetchError("Maven artifact exceeds its byte limit")
                stream.flush()
                os.fsync(stream.fileno())
            if declared_length is not None and total != declared_length:
                raise _RetryableMavenFetchError(
                    "Maven artifact length differs from Content-Length"
                )
            if digest.hexdigest() != expected_digest:
                raise MavenFetchError("Maven artifact digest differs from the manifest")
            # A same-directory hard link is an atomic create-only placement:
            # it cannot overwrite a destination that appeared during download.
            os.link(partial, destination)
            partial.unlink()
            created = False
            return total
    finally:
        if created:
            try:
                partial.unlink()
            except OSError:
                pass


def fetch_cache(
    repository: Path,
    manifest: Path = DEFAULT_MANIFEST,
    *,
    _opener: Any | None = None,
    _attempts: int = _FETCH_ATTEMPTS,
    _sleep: Callable[[float], None] = time.sleep,
) -> tuple[int, str]:
    """Populate a new repository from one fixed origin, then verify every byte."""

    expected = load_manifest(manifest)
    if _attempts < 1:
        raise MavenFetchError("Maven fetch attempts must be positive")
    try:
        repository.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise MavenFetchError("Maven repository must not already exist") from exc
    opener = _opener if _opener is not None else _default_opener()
    downloaded = 0
    for relative, expected_digest in expected.items():
        destination = repository.joinpath(*PurePosixPath(relative).parts)
        url = _artifact_url(relative)
        for attempt in range(1, _attempts + 1):
            try:
                size = _download_once(
                    opener=opener,
                    url=url,
                    destination=destination,
                    expected_digest=expected_digest,
                    remaining_bytes=_MAX_REPOSITORY_BYTES - downloaded,
                )
                downloaded += size
                break
            except _RetryableMavenFetchError:
                if attempt == _attempts:
                    raise
                _sleep(float(attempt))
        else:  # pragma: no cover - the retry loop either breaks or raises
            raise MavenFetchError("Maven artifact fetch did not terminate")
    return verify_cache(repository, manifest)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        count, digest = fetch_cache(args.repository)
    except (ConformanceIOError, MavenCacheError, MavenFetchError, OSError) as exc:
        parser.error(str(exc))
    print(
        f"fetched and verified {count} Maven JAR/POM artifacts from "
        f"{MAVEN_CENTRAL_ORIGIN}; manifest sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["MAVEN_CENTRAL_ORIGIN", "MavenFetchError", "fetch_cache"]
