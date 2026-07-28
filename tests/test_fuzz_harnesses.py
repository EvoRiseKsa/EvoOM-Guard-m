"""Deterministic smoke coverage for the ClusterFuzzLite targets."""

from __future__ import annotations

import random
from pathlib import Path

from tools.fuzz import junit_fuzzer, strict_json_fuzzer

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tools" / "fuzz" / "corpus"
BUILD_SCRIPT = ROOT / ".clusterfuzzlite" / "build.sh"


def test_committed_seed_corpora_are_executable() -> None:
    targets = {
        "strict_json_fuzzer": strict_json_fuzzer.fuzz_one_input,
        "junit_fuzzer": junit_fuzzer.fuzz_one_input,
    }
    for name, target in targets.items():
        seeds = sorted((CORPUS / name).iterdir())
        assert seeds
        for seed in seeds:
            target(seed.read_bytes())


def test_fuzz_targets_survive_reproducible_mutation_smoke() -> None:
    generator = random.Random(0xE60A4D)
    targets = (
        strict_json_fuzzer.fuzz_one_input,
        junit_fuzzer.fuzz_one_input,
    )
    for _ in range(1_000):
        data = generator.randbytes(generator.randrange(0, 2_048))
        for target in targets:
            target(data)


def test_clusterfuzz_build_uses_the_selected_sanitizer_runtime() -> None:
    text = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert "compile_python_fuzzer" in text
    assert "asan_with_fuzzer.so" in text
    assert "ubsan_with_fuzzer.so" in text
    assert r'LD_PRELOAD="\$this_dir/sanitizer_with_fuzzer.so"' in text
    assert "unsupported sanitizer" in text
