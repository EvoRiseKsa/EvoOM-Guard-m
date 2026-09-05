"""Verify the exact Maven artifacts used by extended live-runner evidence."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from tools.conformance.secure_io import ConformanceIOError, read_stable_regular_file

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    REPOSITORY_ROOT / "tools" / "ci-live-runners" / "maven" / "artifacts.sha256"
)
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACTS = 1000
_LINE_RE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9_.+/-]+\.(?:jar|pom))")


class MavenCacheError(ValueError):
    """The Maven cache differs from the reviewed artifact inventory."""


def _is_link_or_reparse(info: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(info.st_mode) or bool(
        marker and getattr(info, "st_file_attributes", 0) & marker
    )


def _parse_manifest(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise MavenCacheError("Maven artifact manifest is not UTF-8") from exc
    if not text.endswith("\n") or "\r" in text:
        raise MavenCacheError("Maven artifact manifest must use canonical LF lines")
    lines = text.removesuffix("\n").split("\n")
    if not lines or len(lines) > MAX_ARTIFACTS or lines != sorted(lines, key=lambda line: line[66:]):
        raise MavenCacheError("Maven artifact manifest is empty, oversized, or unsorted")
    result: dict[str, str] = {}
    for line in lines:
        match = _LINE_RE.fullmatch(line)
        if match is None:
            raise MavenCacheError("Maven artifact manifest has an invalid line")
        digest, relative = match.groups()
        manifest_path = PurePosixPath(relative)
        parts = manifest_path.parts
        if (
            manifest_path.is_absolute()
            or manifest_path.as_posix() != relative
            or not parts
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise MavenCacheError("Maven artifact path is unsafe")
        if relative in result:
            raise MavenCacheError("Maven artifact manifest contains a duplicate path")
        result[relative] = digest
    return result


def _load_manifest_snapshot(path: Path) -> tuple[dict[str, str], str]:
    raw = read_stable_regular_file(
        path,
        label="Maven artifact manifest",
        max_bytes=256 * 1024,
    )
    return _parse_manifest(raw), hashlib.sha256(raw).hexdigest()


def load_manifest(path: Path) -> dict[str, str]:
    """Load a canonical, sorted, traversal-free SHA-256 inventory."""

    expected, _digest = _load_manifest_snapshot(path)
    return expected


def _artifact_paths(repository: Path) -> dict[str, Path]:
    declared = repository.lstat()
    if _is_link_or_reparse(declared) or not stat.S_ISDIR(declared.st_mode):
        raise MavenCacheError("Maven repository must be a real directory")
    resolved = repository.resolve(strict=True)
    if not resolved.is_dir():
        raise MavenCacheError("Maven repository must be a real directory")
    artifacts: dict[str, Path] = {}
    for current, directories, filenames in os.walk(resolved, followlinks=False):
        current_path = Path(current)
        for directory in tuple(directories):
            child = (current_path / directory).lstat()
            if _is_link_or_reparse(child):
                raise MavenCacheError("Maven repository contains a symlinked directory")
            if not stat.S_ISDIR(child.st_mode):
                raise MavenCacheError("Maven repository contains a non-directory entry")
        for filename in filenames:
            path = current_path / filename
            if path.suffix not in {".jar", ".pom"}:
                continue
            if path.is_symlink():
                raise MavenCacheError("Maven repository contains a symlinked artifact")
            relative = path.relative_to(resolved).as_posix()
            if relative in artifacts:
                raise MavenCacheError("Maven repository contains a duplicate artifact path")
            artifacts[relative] = path
            if len(artifacts) > MAX_ARTIFACTS:
                raise MavenCacheError("Maven repository artifact inventory is oversized")
    return artifacts


def verify_cache(repository: Path, manifest: Path = DEFAULT_MANIFEST) -> tuple[int, str]:
    """Require the repository's JAR/POM set and bytes to match the manifest."""

    expected, manifest_digest = _load_manifest_snapshot(manifest)
    observed = _artifact_paths(repository)
    missing = sorted(expected.keys() - observed.keys())
    extra = sorted(observed.keys() - expected.keys())
    if missing or extra:
        raise MavenCacheError(
            f"Maven artifact inventory differs: missing={missing}, extra={extra}"
        )
    for relative, digest in expected.items():
        raw = read_stable_regular_file(
            observed[relative],
            label=f"Maven artifact {relative}",
            max_bytes=MAX_ARTIFACT_BYTES,
        )
        if hashlib.sha256(raw).hexdigest() != digest:
            raise MavenCacheError(f"Maven artifact digest differs: {relative}")
    return len(expected), manifest_digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        count, digest = verify_cache(args.repository, args.manifest)
    except (ConformanceIOError, MavenCacheError, OSError) as exc:
        parser.error(str(exc))
    print(f"verified {count} Maven JAR/POM artifacts; manifest sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
