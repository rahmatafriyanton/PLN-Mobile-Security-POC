#!/usr/bin/env bash
set -euo pipefail

PACKAGE="com.app.plnmobile"
ACTIVITY="$PACKAGE/.MainActivity"
PROVIDER="com.app.plnmobile.kuvakkvnefqkhbjgcavpyekackbucbqbxbkxgmircpcvlb"
EXPECTED_SHA256="e34d6acb7f76c9a65f7764ae32c607b617d121ce98a587d5e63db0de34b44a59"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_APK="${INPUT_APK:-$SCRIPT_DIR/eK1tY8mL4w.apk}"
OUTPUT_APK="${OUTPUT_APK:-$SCRIPT_DIR/build/pln-zimpe-standalone.apk}"
KEYSTORE="${KEYSTORE:-$HOME/.android/debug.keystore}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
BUILD_TOOLS="${BUILD_TOOLS:-$ANDROID_SDK_ROOT/build-tools/35.0.0}"
FRIDA_BIN="${FRIDA_BIN:-$(command -v frida || true)}"
[[ -n "$FRIDA_BIN" ]] || FRIDA_BIN="$HOME/.pyenv/versions/frida-16.5.2/bin/frida"
MODE="${1:-full}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pln-zimpe.XXXXXX")"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

progress() {
  printf '\033[1;36m[%3d%%]\033[0m %s\n' "$1" "$2"
}

die() {
  echo "[error] $*" >&2
  exit 1
}

resolve_device() {
  SERIAL="${ANDROID_SERIAL:-$(adb devices | awk '$2 == "device" {print $1; exit}')}"
  [[ -n "$SERIAL" ]] || die "Tidak ada perangkat ADB yang ready"
}

launch_and_attach() {
  resolve_device
  [[ -x "$FRIDA_BIN" ]] || die "Frida tidak ditemukan: $FRIDA_BIN"
  [[ -f "$SCRIPT_DIR/frida-injected.js" ]] || die "frida-injected.js tidak ditemukan"

  progress 88 "Starting target..."
  adb -s "$SERIAL" shell am force-stop "$PACKAGE" >/dev/null 2>&1
  adb -s "$SERIAL" shell am start -n "$ACTIVITY" >/dev/null

  local pid=""
  for _ in $(seq 1 100); do
    pid="$(adb -s "$SERIAL" shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r' || true)"
    [[ -n "$pid" ]] && break
    sleep 0.05
  done
  [[ -n "$pid" ]] || die "Proses aplikasi tidak muncul"

  sleep 3
  [[ "$(adb -s "$SERIAL" shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r')" == "$pid" ]] ||
    die "Aplikasi berhenti sebelum injection"

  progress 100 "Injecting..."
  cleanup
  trap - EXIT INT TERM
  exec "$FRIDA_BIN" -D "$SERIAL" -p "$pid" -l "$SCRIPT_DIR/frida-injected.js"
}

case "$MODE" in
  --frida-only)
    launch_and_attach
    ;;
  full|--build-only)
    ;;
  *)
    die "Gunakan: $0 [--build-only|--frida-only]"
    ;;
esac

for tool in adb apktool awk shasum; do
  command -v "$tool" >/dev/null || die "Tool tidak ditemukan: $tool"
done
[[ -x "$BUILD_TOOLS/zipalign" ]] || die "zipalign tidak ditemukan"
[[ -x "$BUILD_TOOLS/apksigner" ]] || die "apksigner tidak ditemukan"
[[ -f "$KEYSTORE" ]] || die "Debug keystore tidak ditemukan"
[[ -f "$INPUT_APK" ]] || die "APK sumber tidak ditemukan"

progress 5 "Validating target..."
actual_sha="$(shasum -a 256 "$INPUT_APK" | awk '{print $1}')"
[[ "$actual_sha" == "$EXPECTED_SHA256" ]] ||
  die "APK sumber tidak cocok: $actual_sha"

progress 15 "Preparing target..."
apktool d -f -q "$INPUT_APK" -o "$WORK/decoded" >"$WORK/build.log" 2>&1 ||
  die "Gagal menyiapkan APK"

manifest="$WORK/decoded/AndroidManifest.xml"
[[ "$(grep -Fc "android:name=\"$PROVIDER\"" "$manifest")" == 1 ]] ||
  die "Provider target tidak ditemukan secara unik"

progress 40 "Applying injection compatibility..."
awk -v provider="$PROVIDER" 'index($0, "android:name=\"" provider "\"") == 0' \
  "$manifest" >"$WORK/AndroidManifest.xml"
mv "$WORK/AndroidManifest.xml" "$manifest"
grep -Fq "android:name=\"$PROVIDER\"" "$manifest" &&
  die "Provider target masih aktif"

progress 60 "Building target..."
mkdir -p "$(dirname "$OUTPUT_APK")"
apktool b -q "$WORK/decoded" -o "$WORK/unsigned.apk" >>"$WORK/build.log" 2>&1 ||
  die "Build gagal"
"$BUILD_TOOLS/zipalign" -f -p 4 "$WORK/unsigned.apk" "$WORK/aligned.apk" \
  >>"$WORK/build.log" 2>&1 || die "Alignment gagal"

progress 75 "Signing target..."
"$BUILD_TOOLS/apksigner" sign \
  --ks "$KEYSTORE" \
  --ks-pass pass:android \
  --key-pass pass:android \
  --out "$OUTPUT_APK" \
  "$WORK/aligned.apk" >>"$WORK/build.log" 2>&1 || die "Signing gagal"
"$BUILD_TOOLS/apksigner" verify "$OUTPUT_APK" >/dev/null 2>&1 ||
  die "Verifikasi APK gagal"

if [[ "$MODE" == "--build-only" ]]; then
  progress 100 "Target ready: $OUTPUT_APK"
  exit 0
fi

progress 82 "Deploying target..."
resolve_device
adb -s "$SERIAL" uninstall "$PACKAGE" >/dev/null 2>&1 || true
adb -s "$SERIAL" install "$OUTPUT_APK" >/dev/null 2>&1 ||
  die "Install gagal pada $SERIAL"
launch_and_attach
