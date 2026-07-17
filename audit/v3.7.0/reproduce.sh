#!/usr/bin/env bash
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.

# Verify the immutable EvoOM Guard v3.7.0 review target without executing a
# candidate repository or using signing material. This is an artifact and source
# identity check, not an independent security assessment.

set -euo pipefail

readonly REPOSITORY="EvoRiseKsa/EvoOM-Guard-m"
readonly TAG="v3.7.0"
readonly COMMIT="1f0ceae5009198b1bf161a3a07fced54c1f01337"
readonly PYZ_SHA256="1d36f7ec45f47f9f6c3178a25a58accf8f8beb0ffd9d29e7bf93b7fe17ad3ec9"
readonly SUMS_SHA256="bc7c85aa06f29298e6ee1af2ad793c6164ede9b9162474f66344dfe9227980c7"
readonly PYZ_SIZE="852118"
readonly SUMS_SIZE="80"
readonly PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [output-directory]" >&2
  exit 64
fi

out_dir="${1:-$(pwd)/evoguard-v3.7.0-review}"
if [[ -e "$out_dir" ]]; then
  if [[ -d "$out_dir" ]] && [[ -z "$(find "$out_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    :
  else
    echo "refusing to write into a non-empty path: $out_dir" >&2
    exit 73
  fi
fi

for command in gh git sha256sum cmp "$PYTHON_BIN"; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command not found: $command" >&2
    exit 69
  }
done

mkdir -p "$out_dir"
release_dir="$out_dir/release"
source_dir="$out_dir/source"
mkdir -p "$release_dir"

echo "== GitHub release attestation =="
gh release verify "$TAG" --repo "$REPOSITORY"

echo "== Download immutable assets =="
gh release download "$TAG" --repo "$REPOSITORY" --dir "$release_dir" \
  --pattern evo-guard.pyz --pattern SHA256SUMS

actual_pyz_sha256="$(sha256sum "$release_dir/evo-guard.pyz" | awk '{print $1}')"
actual_sums_sha256="$(sha256sum "$release_dir/SHA256SUMS" | awk '{print $1}')"
[[ "$actual_pyz_sha256" == "$PYZ_SHA256" ]] || {
  echo "evo-guard.pyz SHA-256 mismatch: $actual_pyz_sha256" >&2
  exit 65
}
[[ "$actual_sums_sha256" == "$SUMS_SHA256" ]] || {
  echo "SHA256SUMS SHA-256 mismatch: $actual_sums_sha256" >&2
  exit 65
}
[[ "$(wc -c < "$release_dir/evo-guard.pyz" | tr -d '[:space:]')" == "$PYZ_SIZE" ]] || {
  echo "evo-guard.pyz size mismatch" >&2
  exit 65
}
[[ "$(wc -c < "$release_dir/SHA256SUMS" | tr -d '[:space:]')" == "$SUMS_SIZE" ]] || {
  echo "SHA256SUMS size mismatch" >&2
  exit 65
}
printf '%s  %s\n' "$PYZ_SHA256" evo-guard.pyz | cmp -s - "$release_dir/SHA256SUMS" || {
  echo "SHA256SUMS content mismatch" >&2
  exit 65
}
( cd "$release_dir" && sha256sum -c SHA256SUMS )

echo "== Resolve fixed source tag =="
git clone --quiet --depth 1 --branch "$TAG" "https://github.com/${REPOSITORY}.git" "$source_dir"
actual_commit="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$actual_commit" == "$COMMIT" ]] || {
  echo "tag resolved to unexpected commit: $actual_commit" >&2
  exit 65
}

echo "== Released zipapp smoke check =="
[[ "$("$PYTHON_BIN" -I "$release_dir/evo-guard.pyz" version)" == "evo-guard 3.7.0" ]]
"$PYTHON_BIN" -I "$release_dir/evo-guard.pyz" doctor

printf '\nVerified target:\n  release: %s\n  commit:  %s\n  pyz:     %s\n' \
  "$TAG" "$COMMIT" "$PYZ_SHA256"
