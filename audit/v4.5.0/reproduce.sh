#!/usr/bin/env bash
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Source-available - see LICENSE for permitted use.

set -euo pipefail

readonly REPOSITORY="EvoRiseKsa/EvoOM-Guard-m"
readonly TAG="v4.5.0"
readonly RELEASE_ID="363544789"
readonly PUBLISHED_AT="2026-08-01T14:32:33Z"
readonly COMMIT="6bb4c328e56661b661e50532886802c6ba36a997"
readonly TREE="bd81a595ca8608ad7da04390f31d5e489f5083ef"
readonly TAG_CI_RUN="30703985270"
readonly PYZ_SHA256="44bf036666bc7bb2903b647f33b63254771771887de4f170c91e8cdd8307c89d"
readonly SPDX_SHA256="d073198e6a3a7d565895b3cf885c95386768670a243e05e5b1471636a0f8da4b"
readonly SUMS_SHA256="0172d35b903661328f16366517fe5a8f666aaf282cf26c5ec4e263da4abedd0f"
readonly PYZ_SIZE="2356398"
readonly SPDX_SIZE="99797"
readonly SUMS_SIZE="166"
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
      if [[ -z "$out_dir" ]]; then
        out_dir="$arg"
      else
        echo "usage: $0 [--smoke] [output-directory]" >&2
        exit 64
      fi
      ;;
  esac
done
out_dir="${out_dir:-$(pwd)/evoguard-v4.5.0-review}"

if [[ -e "$out_dir" || -L "$out_dir" ]]; then
  if [[ ! -d "$out_dir" ]] || [[ -L "$out_dir" ]] || \
    [[ -n "$(find "$out_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "refusing to write into a link, non-directory, or non-empty path: $out_dir" >&2
    exit 73
  fi
fi

for command in gh git sha256sum cmp cut find sort wc tr; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command not found: $command" >&2
    exit 69
  }
done
if [[ "$run_smoke" == true ]]; then
  command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
    echo "required command not found for --smoke: $PYTHON_BIN" >&2
    exit 69
  }
fi

mkdir -p "$out_dir/release"

echo "== GitHub Release attestation =="
gh release verify "$TAG" --repo "$REPOSITORY"

echo "== Exact immutable Release metadata =="
actual_release="$({
  gh api "repos/$REPOSITORY/releases/tags/$TAG" \
    --jq '[.id,.tag_name,.target_commitish,.published_at,(.immutable|tostring)]|@tsv'
})"
expected_release="${RELEASE_ID}"$'\t'"${TAG}"$'\t'"${COMMIT}"$'\t'"${PUBLISHED_AT}"$'\ttrue'
if [[ "$actual_release" != "$expected_release" ]]; then
  echo "release metadata mismatch: $actual_release" >&2
  exit 1
fi

actual_assets="$({
  gh api "repos/$REPOSITORY/releases/tags/$TAG" \
    --jq '.assets|sort_by(.name)[]|[.name,(.size|tostring),.digest,(.id|tostring)]|@tsv'
})"
expected_assets="SHA256SUMS"$'\t'"${SUMS_SIZE}"$'\t'"sha256:${SUMS_SHA256}"$'\t497974098\n'"evo-guard.pyz"$'\t'"${PYZ_SIZE}"$'\t'"sha256:${PYZ_SHA256}"$'\t497974096\n'"evo-guard.spdx.json"$'\t'"${SPDX_SIZE}"$'\t'"sha256:${SPDX_SHA256}"$'\t497974097'
if [[ "$actual_assets" != "$expected_assets" ]]; then
  echo "release asset metadata mismatch" >&2
  exit 1
fi

echo "== Download and hash the exact asset set =="
gh release download "$TAG" --repo "$REPOSITORY" --dir "$out_dir/release" \
  --pattern evo-guard.pyz --pattern evo-guard.spdx.json --pattern SHA256SUMS

mapfile -t asset_names < <(
  find "$out_dir/release" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort
)
expected_names=("SHA256SUMS" "evo-guard.pyz" "evo-guard.spdx.json")
if [[ "${asset_names[*]}" != "${expected_names[*]}" ]]; then
  echo "downloaded asset set mismatch: ${asset_names[*]}" >&2
  exit 1
fi

actual_pyz_sha256="$(sha256sum "$out_dir/release/evo-guard.pyz" | cut -d ' ' -f 1)"
actual_spdx_sha256="$(sha256sum "$out_dir/release/evo-guard.spdx.json" | cut -d ' ' -f 1)"
actual_sums_sha256="$(sha256sum "$out_dir/release/SHA256SUMS" | cut -d ' ' -f 1)"
[[ "$actual_pyz_sha256" == "$PYZ_SHA256" ]]
[[ "$actual_spdx_sha256" == "$SPDX_SHA256" ]]
[[ "$actual_sums_sha256" == "$SUMS_SHA256" ]]
[[ "$(wc -c < "$out_dir/release/evo-guard.pyz" | tr -d '[:space:]')" == "$PYZ_SIZE" ]]
[[ "$(wc -c < "$out_dir/release/evo-guard.spdx.json" | tr -d '[:space:]')" == "$SPDX_SIZE" ]]
[[ "$(wc -c < "$out_dir/release/SHA256SUMS" | tr -d '[:space:]')" == "$SUMS_SIZE" ]]

{
  printf '%s  %s\n' "$PYZ_SHA256" evo-guard.pyz
  printf '%s  %s\n' "$SPDX_SHA256" evo-guard.spdx.json
} | cmp -s - "$out_dir/release/SHA256SUMS"
( cd "$out_dir/release" && sha256sum -c SHA256SUMS )

echo "== Resolve fixed source tag and tree =="
git clone --quiet --depth 1 --branch "$TAG" \
  "https://github.com/${REPOSITORY}.git" "$out_dir/source"
[[ "$(git -C "$out_dir/source" rev-parse HEAD)" == "$COMMIT" ]]
[[ "$(git -C "$out_dir/source" rev-parse 'HEAD^{tree}')" == "$TREE" ]]

echo "== Confirm expected unsigned commit observation =="
actual_commit_verification="$({
  gh api "repos/$REPOSITORY/commits/$COMMIT" \
    --jq '[.commit.verification.verified,.commit.verification.reason]|map(tostring)|@tsv'
})"
if [[ "$actual_commit_verification" != $'false\tunsigned' ]]; then
  echo "unexpected commit verification state: $actual_commit_verification" >&2
  exit 1
fi

echo "== Pin successful tag CI observation =="
actual_tag_ci="$({
  gh run view "$TAG_CI_RUN" --repo "$REPOSITORY" \
    --json databaseId,event,headBranch,headSha,status,conclusion \
    --jq '[.databaseId,.event,.headBranch,.headSha,.status,.conclusion]|map(tostring)|@tsv'
})"
expected_tag_ci="${TAG_CI_RUN}"$'\tpush\t'"${TAG}"$'\t'"${COMMIT}"$'\tcompleted\tsuccess'
if [[ "$actual_tag_ci" != "$expected_tag_ci" ]]; then
  echo "tag CI metadata mismatch: $actual_tag_ci" >&2
  exit 1
fi

if [[ "$run_smoke" == true ]]; then
  echo "== Optional released zipapp smoke check =="
  [[ "$("$PYTHON_BIN" -I "$out_dir/release/evo-guard.pyz" version)" == "evo-guard 4.5.0" ]]
  "$PYTHON_BIN" -I "$out_dir/release/evo-guard.pyz" doctor
fi

printf '\nVerified frozen target identity:\n  release: %s\n  commit:  %s (GitHub: unsigned)\n  tree:    %s\n  pyz:     %s\n  SPDX:    %s\n' \
  "$TAG" "$COMMIT" "$TREE" "$PYZ_SHA256" "$SPDX_SHA256"
