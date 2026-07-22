#!/usr/bin/env bash
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.

set -euo pipefail

readonly REPOSITORY="EvoRiseKsa/EvoOM-Guard-m"
readonly TAG="v4.1.0"
readonly COMMIT="16029f3e34237ed07b97649c5c9be35d0a356bf7"
readonly TREE="7c749ed298050840fdd52577e6364a6e63cd36a6"
readonly PYZ_SHA256="d5ce7dbefa870307d6fe49ddec1e9847cad89d15f6afe2b74f4e7b8953fc62b2"
readonly SUMS_SHA256="2e9839e838d9384a2f7200f9caddb336ffe043cd971f8151c9d3efb090fa4c3b"
readonly PYZ_SIZE="1388088"
readonly SUMS_SIZE="80"
readonly PYTHON_BIN="${PYTHON_BIN:-python3}"

run_smoke=false
out_dir=""
for arg in "$@"; do
  case "$arg" in
    --smoke) run_smoke=true ;;
    --help|-h)
      echo "usage: $0 [--smoke] [output-directory]"
      exit 0
      ;;
    *)
      if [[ -z "$out_dir" ]]; then out_dir="$arg"; else
        echo "usage: $0 [--smoke] [output-directory]" >&2
        exit 64
      fi
      ;;
  esac
done
out_dir="${out_dir:-$(pwd)/evoguard-v4.1.0-review}"

if [[ -e "$out_dir" ]]; then
  if [[ ! -d "$out_dir" ]] || [[ -n "$(find "$out_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "refusing to write into a non-empty path: $out_dir" >&2
    exit 73
  fi
fi

for command in gh git sha256sum cmp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command not found: $command" >&2
    exit 69
  }
done
if [[ "$run_smoke" == true ]]; then command -v "$PYTHON_BIN" >/dev/null 2>&1; fi

mkdir -p "$out_dir/release"

echo "== GitHub release attestation =="
gh release verify "$TAG" --repo "$REPOSITORY"

echo "== Download immutable assets =="
gh release download "$TAG" --repo "$REPOSITORY" --dir "$out_dir/release" \
  --pattern evo-guard.pyz --pattern SHA256SUMS

actual_pyz_sha256="$(sha256sum "$out_dir/release/evo-guard.pyz" | awk '{print $1}')"
actual_sums_sha256="$(sha256sum "$out_dir/release/SHA256SUMS" | awk '{print $1}')"
[[ "$actual_pyz_sha256" == "$PYZ_SHA256" ]]
[[ "$actual_sums_sha256" == "$SUMS_SHA256" ]]
[[ "$(wc -c < "$out_dir/release/evo-guard.pyz" | tr -d '[:space:]')" == "$PYZ_SIZE" ]]
[[ "$(wc -c < "$out_dir/release/SHA256SUMS" | tr -d '[:space:]')" == "$SUMS_SIZE" ]]
printf '%s  %s\n' "$PYZ_SHA256" evo-guard.pyz | cmp -s - "$out_dir/release/SHA256SUMS"
( cd "$out_dir/release" && sha256sum -c SHA256SUMS )

echo "== Resolve fixed source tag =="
git clone --quiet --depth 1 --branch "$TAG" "https://github.com/${REPOSITORY}.git" "$out_dir/source"
[[ "$(git -C "$out_dir/source" rev-parse HEAD)" == "$COMMIT" ]]
[[ "$(git -C "$out_dir/source" rev-parse 'HEAD^{tree}')" == "$TREE" ]]
[[ "$(gh api "repos/$REPOSITORY/commits/$COMMIT" --jq '.commit.verification.verified')" == "true" ]]
[[ "$(gh api "repos/$REPOSITORY/commits/$COMMIT" --jq '.commit.verification.reason')" == "valid" ]]

if [[ "$run_smoke" == true ]]; then
  echo "== Optional released zipapp smoke check =="
  [[ "$("$PYTHON_BIN" -I "$out_dir/release/evo-guard.pyz" version)" == "evo-guard 4.1.0" ]]
  "$PYTHON_BIN" -I "$out_dir/release/evo-guard.pyz" doctor
fi

printf '\nVerified target:\n  release: %s\n  commit:  %s\n  tree:    %s\n  pyz:     %s\n' \
  "$TAG" "$COMMIT" "$TREE" "$PYZ_SHA256"
