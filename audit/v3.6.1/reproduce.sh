#!/usr/bin/env bash
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.

# Verify the immutable EvoOM Guard v3.6.1 review target without executing a
# candidate repository or using any signing material.  This is an artifact and
# source-identity check, not an independent security assessment.

set -euo pipefail

readonly REPOSITORY="EvoRiseKsa/EvoOM-Guard-m"
readonly TAG="v3.6.1"
readonly COMMIT="23c388773581e65501e733f88d158113e0095830"
readonly PYZ_SHA256="4d3e074d707ffdae70e4b3d78e786245c77fd6bdc51782eb1b3f8c4ed0e12a34"
readonly SUMS_SHA256="da970e6e53b0fd9dd4ea5bfee8ee05037e74886aeb661b821223dcaf7b968372"
readonly PYZ_SIZE="770287"
readonly SUMS_SIZE="80"
readonly PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [output-directory]" >&2
  exit 64
fi

out_dir="${1:-$(pwd)/evoguard-v3.6.1-review}"
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
[[ "$("$PYTHON_BIN" -I "$release_dir/evo-guard.pyz" version)" == "evo-guard 3.6.1" ]]
"$PYTHON_BIN" -I "$release_dir/evo-guard.pyz" doctor

printf '\nVerified target:\n  release: %s\n  commit:  %s\n  pyz:     %s\n' \
  "$TAG" "$COMMIT" "$PYZ_SHA256"
