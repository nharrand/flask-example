#!/bin/bash -eu
# Build & package Python fuzzers as single binaries with pyinstaller, as recommended.
# Note: no native C/C++ extensions, so we do NOT LD_PRELOAD sanitizer libs in the wrapper.

# Ensure pyinstaller is present
pip3 install pyinstaller

# Optionally "install" the project (useful if it had C extensions)
# pip3 install .

for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  base=$(basename -s .py "$fuzzer")
  pkg="${base}.pkg"

  pyinstaller --distpath "$OUT" --onefile --name "$pkg" "$fuzzer"

  cat > "$OUT/$base" <<'EOF'
#!/bin/sh
# Simple wrapper that launches the packaged fuzzer.
this_dir=$(dirname "$0")
"$this_dir"/'"$pkg"' "$@"
EOF
  chmod +x "$OUT/$base"
done
