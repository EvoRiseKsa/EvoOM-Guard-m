#!/bin/bash
set -euo pipefail

project_root="$SRC/evoom-guard"

python3 -m pip install --no-deps --no-build-isolation "$project_root"

atheris_lib_dir="$(
  python3 -c 'import atheris; print(atheris.path())'
)"
case "$SANITIZER" in
  address)
    cp "$atheris_lib_dir/asan_with_fuzzer.so" \
      "$OUT/sanitizer_with_fuzzer.so"
    ;;
  undefined)
    cp "$atheris_lib_dir/ubsan_with_fuzzer.so" \
      "$OUT/sanitizer_with_fuzzer.so"
    ;;
  *)
    echo "unsupported sanitizer: $SANITIZER" >&2
    exit 2
    ;;
esac
cp "$(command -v llvm-symbolizer)" "$OUT/llvm-symbolizer"

for target in strict_json_fuzzer junit_fuzzer; do
  compile_python_fuzzer \
    "$project_root/tools/fuzz/${target}.py"
  chmod 0755 "$OUT/${target}.pkg"

  cat >"$OUT/$target" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput
this_dir=\$(CDPATH= cd -- "\$(dirname -- "\$0")" && pwd)
exec env \
  LD_PRELOAD="\$this_dir/sanitizer_with_fuzzer.so" \
  ASAN_OPTIONS="\${ASAN_OPTIONS:-}:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0" \
  "\$this_dir/${target}.pkg" "\$@"
EOF
  chmod 0755 "$OUT/$target"

  python3 -m zipfile -c \
    "$OUT/${target}_seed_corpus.zip" \
    "$project_root/tools/fuzz/corpus/$target"
done

cp "$project_root/tools/fuzz/junit_fuzzer.dict" "$OUT/junit_fuzzer.dict"
