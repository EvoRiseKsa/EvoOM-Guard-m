import hashlib
import json
from pathlib import Path

BASELINE = Path(__file__).resolve().parents[1] / "tests" / "baseline" / "v4.0.1"
MANIFEST = BASELINE / "BASELINE_MANIFEST.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _assert_file_matches(entry: dict) -> None:
    rel = Path(entry["path"].replace("\\", "/"))
    target = BASELINE / rel
    assert target.exists(), f"missing baseline asset: {rel}"
    assert target.is_file()
    assert entry["sha256"] == sha256(target)
    assert entry["size_bytes"] == target.stat().st_size


def test_baseline_manifest_is_present_and_valid() -> None:
    manifest = _load_manifest()
    assert manifest["schema_version"] == "baseline-v1"
    assert manifest["source_version"] == "4.0.1"
    assert manifest["release"]["status"] == "pre-release"
    assert manifest["evidence_formats"]["record_schema"] == "1.11"
    assert manifest["evidence_formats"]["sarif"] == "2.1.0"


def test_baseline_command_artifacts_match_manifest() -> None:
    manifest = _load_manifest()
    for item in manifest["command_manifest"]["inventory"]:
        _assert_file_matches(item["artifact"])


def test_baseline_evidence_assets_match_manifest() -> None:
    manifest = _load_manifest()
    for variant in manifest["artifact_vectors"]["command_output"].values():
        _assert_file_matches(variant["record"])
        _assert_file_matches(variant["report"])
        _assert_file_matches(variant["sarif"])


def test_baseline_pack_and_signature_assets_match_manifest() -> None:
    manifest = _load_manifest()
    _assert_file_matches(manifest["artifact_vectors"]["pack_digest_vector"])
    sigset = manifest["artifact_vectors"]["signed_record"]
    _assert_file_matches(sigset["record"])
    _assert_file_matches(sigset["signature"])
    _assert_file_matches(sigset["pubkey"])


def test_baseline_release_asset_checksums_match_manifest_and_file() -> None:
    manifest = _load_manifest()
    _assert_file_matches(manifest["release"]["asset"])
    checks = BASELINE / manifest["release"].get("source_ref", "SHA256SUMS_v4.0.1.txt")
    if checks.name != "SHA256SUMS_v4.0.1.txt":
        checks = BASELINE / "SHA256SUMS_v4.0.1.txt"
    assert checks.exists()
    lines = [line.strip() for line in checks.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines, "baseline checksum file is empty"


def test_baseline_references_expected_benchmark_digest() -> None:
    manifest = _load_manifest()
    bench = Path(manifest["benchmarks"]["results_path"])
    expected = manifest["benchmarks"]["results_sha256"]
    actual = sha256((BASELINE.parents[2] / bench).resolve())
    assert actual == expected
    assert manifest["benchmarks"]["rows"] == 16
