#!/usr/bin/env bash
# Encrypts sample files with the real topal-cli and checks them with the independent
# Python reader in this folder.
#
#   pip install argon2-cffi pynacl
#   cargo build --release -p topal
#   tools/check.sh
#
# Everything happens in a temporary folder; your own recovery key setting is not touched.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
cli="${TOPAL_CLI:-$root/target/release/topal-cli}"
python="${PYTHON:-python}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
native() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else echo "$1"; fi; }

mkdir -p "$work/appdata" "$work/plain/sub/empty dir"
export APPDATA="$(native "$work/appdata")" XDG_CONFIG_HOME="$work/appdata"
head -c 2621441 /dev/urandom > "$work/plain/big.bin"
head -c 5000 /dev/urandom > "$work/plain/صورة.jpg"
echo note > "$work/plain/sub/note.txt"

export TOPAL_PASSWORD=pass-one
"$cli" encrypt "$work/plain/big.bin" "$work/plain/صورة.jpg" -o "$work/by-password" >/dev/null
"$cli" encrypt "$work/plain" --hide-names -o "$work/hidden" >/dev/null
key="$("$cli" recovery create 2>/dev/null)"
"$cli" encrypt "$work/plain/big.bin" -o "$work/with-recovery" >/dev/null 2>&1
cp -r "$work/with-recovery" "$work/changed"
TOPAL_NEW_PASSWORD=pass-new "$cli" change-password "$work/changed" >/dev/null

cd "$here"
PYTHONIOENCODING=utf-8 "$python" check.py "$(native "$work")" "$key" \
  "$(native "$root/core/tests/fixtures/v1-sample.txt.topal")" \
  "$(native "$root/core/tests/fixtures/v1-sample.txt")"
