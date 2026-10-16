#!/usr/bin/env bash
set -euo pipefail

PACKAGE="com.app.plnmobile"
EXPECTED_APK_SHA256="e34d6acb7f76c9a65f7764ae32c607b617d121ce98a587d5e63db0de34b44a59"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="full"
if [[ "${1:-}" == "--build-only" || "${1:-}" == "--frida-only" ]]; then
  MODE="${1#--}"
  shift
fi
INPUT_APK="${1:-$SCRIPT_DIR/eK1tY8mL4w.apk}"
OUTPUT_APK="${2:-$SCRIPT_DIR/build/pln-zimpe-frida-ready.apk}"
SERIAL="${ANDROID_SERIAL:-}"
REMOTE="${FRIDA_REMOTE:-}"
SETTLE_SECONDS="${SETTLE_SECONDS:-45}"
KEYSTORE="${KEYSTORE:-$HOME/.android/debug.keystore}"
FRIDA_BIN="${FRIDA_BIN:-$HOME/.pyenv/versions/frida-16.5.2/bin/frida}"
FRIDA_PS="${FRIDA_PS:-${FRIDA_BIN%/frida}/frida-ps}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
BUILD_TOOLS="${BUILD_TOOLS:-$ANDROID_SDK_ROOT/build-tools/35.0.0}"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pln-zimpe.XXXXXX")"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

die() {
  echo "[error] $*" >&2
  exit 1
}

progress() {
  printf '\033[1;36m[%3s%%]\033[0m %s\n' "$1" "$2"
}

resolve_serial() {
  [[ -n "$SERIAL" ]] && return
  SERIAL="$(adb devices | awk '$2 == "device" { print $1; exit }')"
  [[ -n "$SERIAL" ]] || die "Tidak ada perangkat ADB yang ready"
}

require_common_tools() {
  for tool in adb awk node tail; do
    command -v "$tool" >/dev/null || die "Tool tidak ditemukan: $tool"
  done
  [[ -x "$FRIDA_BIN" ]] || die "frida tidak ditemukan: $FRIDA_BIN"
  [[ -x "$FRIDA_PS" ]] || die "frida-ps tidak ditemukan: $FRIDA_PS"
  [[ -f "$SCRIPT_DIR/pln-test.js" ]] || die "pln-test.js tidak ditemukan"
  [[ -f "$SCRIPT_DIR/frida-injected.js" ]] || die "frida-injected.js tidak ditemukan"
}

launch_and_attach() {
  require_common_tools
  resolve_serial
  local -a frida_connection
  if [[ -n "$REMOTE" ]]; then
    frida_connection=(-H "$REMOTE")
  else
    adb -s "$SERIAL" forward tcp:27043 tcp:27043 >/dev/null
    if "$FRIDA_PS" -H 127.0.0.1:27043 >/dev/null 2>&1; then
      frida_connection=(-H 127.0.0.1:27043)
    elif "$FRIDA_PS" -U >/dev/null 2>&1; then
      frida_connection=(-U)
    else
      die "Frida server tidak dapat dihubungi"
    fi
  fi
  adb -s "$SERIAL" shell am force-stop "$PACKAGE" >/dev/null 2>&1
  adb -s "$SERIAL" shell am start -W -n "$PACKAGE/.MainActivity" >/dev/null

  local pid=""
  for _ in $(seq 1 100); do
    pid="$(adb -s "$SERIAL" shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r')"
    [[ -n "$pid" ]] && break
    sleep 0.1
  done
  [[ -n "$pid" ]] || die "PID aplikasi tidak muncul"

  progress 75 "Initializing target..."
  local elapsed
  for ((elapsed = 1; elapsed <= SETTLE_SECONDS; elapsed++)); do
    sleep 1
    [[ "$(adb -s "$SERIAL" shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r')" == "$pid" ]] ||
      die "Aplikasi berhenti sebelum Frida attach"
    if ((elapsed % 5 == 0 || elapsed == SETTLE_SECONDS)); then
      progress "$((75 + elapsed * 20 / SETTLE_SECONDS))" "Initializing target..."
    fi
  done

  cleanup
  trap - EXIT INT TERM
  progress 100 "Injecting Frida..."
  if [[ -t 0 ]]; then
    exec "$FRIDA_BIN" \
      "${frida_connection[@]}" \
      -p "$pid" \
      -l "$SCRIPT_DIR/pln-test.js" \
      -l "$SCRIPT_DIR/frida-injected.js"
  fi
  tail -f /dev/null | "$FRIDA_BIN" \
    "${frida_connection[@]}" \
    -p "$pid" \
    -l "$SCRIPT_DIR/pln-test.js" \
    -l "$SCRIPT_DIR/frida-injected.js"
}

if [[ "$MODE" == "frida-only" ]]; then
  launch_and_attach
  exit $?
fi

for tool in adb awk node unzip zip shasum; do
  command -v "$tool" >/dev/null || die "Tool tidak ditemukan: $tool"
done
[[ -x "$ZIPALIGN" ]] || die "zipalign tidak ditemukan: $ZIPALIGN"
[[ -x "$APKSIGNER" ]] || die "apksigner tidak ditemukan: $APKSIGNER"
[[ -f "$KEYSTORE" ]] || die "Debug keystore tidak ditemukan: $KEYSTORE"
[[ -f "$INPUT_APK" ]] || die "APK sumber tidak ditemukan: $INPUT_APK"

actual_sha="$(shasum -a 256 "$INPUT_APK" | awk '{print $1}')"
[[ "$actual_sha" == "$EXPECTED_APK_SHA256" ]] || die \
  "APK sumber berbeda. expected=$EXPECTED_APK_SHA256 actual=$actual_sha"

PLAN="$WORK/patch-plan.json"
ENTRY="$(node "$SCRIPT_DIR/pln-test.js" --patch-plan >"$PLAN" &&
  node -e "process.stdout.write(require(process.argv[1]).apkEntry)" "$PLAN")"
LIBRARY="$WORK/stage/$ENTRY"
mkdir -p "$(dirname "$LIBRARY")" "$(dirname "$OUTPUT_APK")"

progress 10 "Preparing injection..."
unzip -p "$INPUT_APK" "$ENTRY" >"$LIBRARY"

progress 35 "Processing target..."
node - "$LIBRARY" "$PLAN" <<'NODE_PATCH'
const fs = require('fs');
const libraryPath = process.argv[2];
const planPath = process.argv[3];
const plan = JSON.parse(fs.readFileSync(planPath, 'utf8'));
const image = fs.readFileSync(libraryPath);
for (const patch of plan.patches) {
  const expected = Buffer.from(patch.expected, 'hex');
  const replacement = Buffer.from(patch.replacement, 'hex');
  const current = image.subarray(patch.offset, patch.offset + expected.length);
  if (!current.equals(expected) && !current.equals(replacement)) {
    throw new Error(`Native signature mismatch at 0x${patch.offset.toString(16)}`);
  }
  replacement.copy(image, patch.offset);
}
fs.writeFileSync(libraryPath, image);
NODE_PATCH

progress 60 "Building injection payload..."
UNALIGNED="$WORK/unaligned.apk"
ALIGNED="$WORK/aligned.apk"
cp "$INPUT_APK" "$UNALIGNED"
(
  cd "$WORK/stage"
  zip -q -0 -u "$UNALIGNED" "$ENTRY"
)
"$ZIPALIGN" -f -p 4 "$UNALIGNED" "$ALIGNED"
"$APKSIGNER" sign \
  --ks "$KEYSTORE" \
  --ks-pass pass:android \
  --key-pass pass:android \
  --out "$OUTPUT_APK" \
  "$ALIGNED"
"$APKSIGNER" verify "$OUTPUT_APK" >/dev/null 2>&1

# Runnable self-check: every verified patch must be present in the signed APK.
unzip -p "$OUTPUT_APK" "$ENTRY" >"$WORK/verify.so"
node - "$WORK/verify.so" "$PLAN" <<'NODE_VERIFY'
const fs = require('fs');
const image = fs.readFileSync(process.argv[2]);
const plan = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
for (const patch of plan.patches) {
  const replacement = Buffer.from(patch.replacement, 'hex');
  const current = image.subarray(patch.offset, patch.offset + replacement.length);
  if (!current.equals(replacement)) {
    throw new Error(`Signed APK verification failed at 0x${patch.offset.toString(16)}`);
  }
}
NODE_VERIFY

if [[ "$MODE" == "build-only" ]]; then
  progress 100 "Injection package ready: $OUTPUT_APK"
  exit 0
fi

progress 70 "Deploying target..."
resolve_serial
adb -s "$SERIAL" uninstall "$PACKAGE" >/dev/null 2>&1 || true
adb -s "$SERIAL" install "$OUTPUT_APK" >/dev/null 2>&1 ||
  die "Install gagal pada $SERIAL"

launch_and_attach
