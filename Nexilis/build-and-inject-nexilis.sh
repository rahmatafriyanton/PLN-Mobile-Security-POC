#!/usr/bin/env bash
set -euo pipefail

PACKAGE="com.app.plnmobile"
EXPECTED_APK_SHA256="03e286af4a7e7728b616fcf6587cb096ec2e67472f0a2e04b95d1316eeef5cce"
PAYLOAD_SHA256="0dd9b08fde9482e89be3b780f46f491722a8aa522a99f8b9b6e6024002f1aeec"
NATIVE_PAYLOAD_SHA256="72ac0d09901925d8b070cd38c114910920d5fbbb2a4894352b69db317b184fe3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_APK="${INPUT_APK:-$SCRIPT_DIR/zX6bQ3nH9v.apk}"
OUTPUT_APK="${OUTPUT_APK:-$SCRIPT_DIR/build/pln-nexilis-standalone.apk}"
KEYSTORE="${KEYSTORE:-$HOME/.android/debug.keystore}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
BUILD_TOOLS="${BUILD_TOOLS:-$ANDROID_SDK_ROOT/build-tools/35.0.0}"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"
FRIDA_BIN="${FRIDA_BIN:-$HOME/.pyenv/versions/frida-16.5.2/bin/frida}"
MODE="${1:-full}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pln-nexilis.XXXXXX")"

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

launch_frida() {
  resolve_device
  [[ -x "$FRIDA_BIN" ]] || die "Frida tidak ditemukan: $FRIDA_BIN"
  [[ -f "$SCRIPT_DIR/emulator/frida-injected.js" ]] ||
    die "frida-injected.js tidak ditemukan"

  progress 96 "Starting target..."
  adb -s "$SERIAL" shell am force-stop "$PACKAGE" >/dev/null 2>&1
  cleanup
  trap - EXIT INT TERM
  progress 100 "Injecting Frida..."
  if [[ -t 0 ]]; then
    exec "$FRIDA_BIN" -D "$SERIAL" -f "$PACKAGE" \
      -l "$SCRIPT_DIR/emulator/frida-injected.js"
  fi
  tail -f /dev/null | "$FRIDA_BIN" -D "$SERIAL" -f "$PACKAGE" \
    -l "$SCRIPT_DIR/emulator/frida-injected.js"
}

case "$MODE" in
  --frida-only)
    launch_frida
    ;;
  full|--build-only)
    ;;
  *)
    die "Gunakan: $0 [--build-only|--frida-only]"
    ;;
esac

for tool in adb apktool awk cp node shasum tail; do
  command -v "$tool" >/dev/null || die "Tool tidak ditemukan: $tool"
done
[[ -x "$ZIPALIGN" ]] || die "zipalign tidak ditemukan: $ZIPALIGN"
[[ -x "$APKSIGNER" ]] || die "apksigner tidak ditemukan: $APKSIGNER"
[[ -f "$KEYSTORE" ]] || die "Debug keystore tidak ditemukan: $KEYSTORE"
[[ -f "$INPUT_APK" ]] || die "APK sumber tidak ditemukan: $INPUT_APK"

PAYLOAD="$SCRIPT_DIR/emulator/src/nexilis_install.bin"
NATIVE_PAYLOAD="$SCRIPT_DIR/emulator/src/nexilis_native_components.snpc"
[[ -f "$PAYLOAD" ]] || die "Payload aplikasi tidak ditemukan"
[[ -f "$NATIVE_PAYLOAD" ]] || die "Payload native tidak ditemukan"

progress 5 "Validating target..."
[[ "$(shasum -a 256 "$INPUT_APK" | awk '{print $1}')" == "$EXPECTED_APK_SHA256" ]] ||
  die "APK sumber tidak cocok"
[[ "$(shasum -a 256 "$PAYLOAD" | awk '{print $1}')" == "$PAYLOAD_SHA256" ]] ||
  die "Payload aplikasi tidak cocok"
[[ "$(shasum -a 256 "$NATIVE_PAYLOAD" | awk '{print $1}')" == "$NATIVE_PAYLOAD_SHA256" ]] ||
  die "Payload native tidak cocok"

progress 15 "Preparing target..."
apktool d -f -q "$INPUT_APK" -o "$WORK/decoded" >"$WORK/build.log" 2>&1 ||
  die "Gagal menyiapkan APK"

progress 40 "Applying injection compatibility..."
node - "$WORK/decoded" <<'NODE_PATCH'
const fs = require('fs');
const path = require('path');
const root = process.argv[2];

function read(relative) {
  return fs.readFileSync(path.join(root, relative), 'utf8');
}

function write(relative, value) {
  fs.writeFileSync(path.join(root, relative), value);
}

function replaceMethod(source, signature, replacement) {
  const start = source.indexOf(signature);
  if (start < 0) throw new Error(`Method not found: ${signature}`);
  const end = source.indexOf('.end method', start);
  if (end < 0) throw new Error(`Method end not found: ${signature}`);
  return source.slice(0, start) + replacement + source.slice(end + 11);
}

const bridgePath = 'smali/com/protector/stub/DexLoaderBridge.smali';
let bridge = read(bridgePath);
bridge = replaceMethod(
  bridge,
  '.method public static native getModernStealthThreatMask(Landroid/content/Context;)J',
  `.method public static getModernStealthThreatMask(Landroid/content/Context;)J
    .locals 2

    const-wide/16 v0, 0x0

    return-wide v0
.end method`
);
bridge = replaceMethod(
  bridge,
  '.method public static synchronized native watchmanVerify()Z',
  `.method public static synchronized watchmanVerify()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method`
);
write(bridgePath, bridge);

const decisionPath = 'smali/com/protector/o/e0.smali';
let decision = read(decisionPath);
decision = replaceMethod(
  decision,
  '.method public static a(Lorg/json/JSONObject;)Z',
  `.method public static a(Lorg/json/JSONObject;)Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method`
);
write(decisionPath, decision);

const appPath = 'smali/com/protector/stub/ProtectorApplication.smali';
let app = read(appPath);
app = replaceMethod(
  app,
  '.method private ensureRegisteredWithRetry(Landroid/content/Context;)Lcom/protector/o/y0;',
  `.method private ensureRegisteredWithRetry(Landroid/content/Context;)Lcom/protector/o/y0;
    .locals 12

    const-string v0, "nexilis_install.bin"
    invoke-static {p1, v0, v0}, Lcom/protector/stub/ProtectorApplication;->extractAssetToTemp(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;

    const-string v0, "nexilis_native_components.snpc"
    invoke-static {p1, v0, v0}, Lcom/protector/stub/ProtectorApplication;->extractAssetToTemp(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;

    new-instance v0, Lcom/protector/o/y0;
    const-string v1, "233f3fa6-aa8e-49eb-89c4-1cd4b4856fc6"
    const-string v2, "0dd9b08fde9482e89be3b780f46f491722a8aa522a99f8b9b6e6024002f1aeec"
    const/4 v3, 0x3
    const-string v4, "891ccde142ec0d1fbde8f7941199ee65f5be6073c8120a5df1401fd838e95231"
    const-string v5, "1285e0f523ddcf39f6ba72812d7958cb855614bd4579bc9f51df81a17a202876"
    const-wide/16 v6, 0x2
    const-string v8, "72ac0d09901925d8b070cd38c114910920d5fbbb2a4894352b69db317b184fe3"
    const/4 v9, 0x0
    const/4 v10, 0x0
    const/4 v11, 0x0
    invoke-direct/range {v0 .. v11}, Lcom/protector/o/y0;-><init>(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;II)V

    return-object v0
.end method`
);
app = replaceMethod(
  app,
  '.method private performKeyDeliveryWithRetry(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Lcom/protector/o/y0;Z)[B',
  `.method private performKeyDeliveryWithRetry(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Lcom/protector/o/y0;Z)[B
    .locals 2

    const-string v0, "yIlhtjsMo3g8qUR+ViIr5UnHHBQ42GukjxeVYTxgeFU="
    const/4 v1, 0x0
    invoke-static {v0, v1}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B
    move-result-object v0

    return-object v0
.end method`
);
write(appPath, app);

const sessionPath = 'smali/com/protector/o/z1.smali';
let session = read(sessionPath);
session = replaceMethod(
  session,
  '.method public static f(Landroid/content/Context;)Ljava/lang/String;',
  `.method public static f(Landroid/content/Context;)Ljava/lang/String;
    .locals 1

    const-string v0, "emulator-provisioned"

    return-object v0
.end method`
);
write(sessionPath, session);

const killSwitchPath = 'smali/com/protector/stub/a.smali';
let killSwitch = read(killSwitchPath);
killSwitch = replaceMethod(
  killSwitch,
  '.method public static b(Landroid/content/Context;Ljava/lang/String;)Z',
  `.method public static b(Landroid/content/Context;Ljava/lang/String;)Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method`
);
write(killSwitchPath, killSwitch);

const nativeStatePath = 'smali/com/protector/o/n0.smali';
let nativeState = read(nativeStatePath);
const nativeMethod =
  '.method public static a(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;';
const nativeStart = nativeState.indexOf(nativeMethod);
const nativeEnd = nativeState.indexOf('.end method', nativeStart);
if (nativeStart < 0 || nativeEnd < 0) throw new Error('Native payload method not found');
const nativeBlock = nativeState
  .slice(nativeStart, nativeEnd + 11)
  .replaceAll('->getNoBackupFilesDir()Ljava/io/File;', '->getFilesDir()Ljava/io/File;');
nativeState =
  nativeState.slice(0, nativeStart) + nativeBlock + nativeState.slice(nativeEnd + 11);
write(nativeStatePath, nativeState);

const verifierPath = 'smali/com/protector/o/v0.smali';
let verifier = read(verifierPath);
verifier = replaceMethod(
  verifier,
  '.method public static a(Ljava/lang/ClassLoader;Landroid/content/Context;ZLjava/lang/String;)V',
  `.method public static a(Ljava/lang/ClassLoader;Landroid/content/Context;ZLjava/lang/String;)V
    .locals 0

    return-void
.end method`
);
write(verifierPath, verifier);

const libraryPath = path.join(root, 'lib/arm64-v8a/libprotector.so');
const image = fs.readFileSync(libraryPath);
for (const patch of [
  { offset: 0x22d6e0, expected: 'ffc301d1fd7b02a9' },
  { offset: 0x223260, expected: 'ff4301d1fd7b03a9' },
]) {
  const expected = Buffer.from(patch.expected, 'hex');
  const replacement = Buffer.from('20008052c0035fd6', 'hex');
  const current = image.subarray(patch.offset, patch.offset + replacement.length);
  if (!current.equals(expected) && !current.equals(replacement)) {
    throw new Error(`Native signature mismatch at 0x${patch.offset.toString(16)}`);
  }
  replacement.copy(image, patch.offset);
}
fs.writeFileSync(libraryPath, image);
NODE_PATCH

cp "$PAYLOAD" "$WORK/decoded/assets/nexilis_install.bin"
cp "$NATIVE_PAYLOAD" "$WORK/decoded/assets/nexilis_native_components.snpc"

progress 65 "Building target..."
mkdir -p "$(dirname "$OUTPUT_APK")"
apktool b -q "$WORK/decoded" -o "$WORK/unsigned.apk" >>"$WORK/build.log" 2>&1 ||
  die "Build gagal"
"$ZIPALIGN" -f -p 4 "$WORK/unsigned.apk" "$WORK/aligned.apk" \
  >>"$WORK/build.log" 2>&1 || die "Alignment gagal"

progress 78 "Signing target..."
"$APKSIGNER" sign \
  --ks "$KEYSTORE" \
  --ks-pass pass:android \
  --key-pass pass:android \
  --out "$OUTPUT_APK" \
  "$WORK/aligned.apk" >>"$WORK/build.log" 2>&1 || die "Signing gagal"
"$APKSIGNER" verify "$OUTPUT_APK" >/dev/null 2>&1 ||
  die "Verifikasi APK gagal"

if [[ "$MODE" == "--build-only" ]]; then
  progress 100 "Target ready: $OUTPUT_APK"
  exit 0
fi

progress 88 "Deploying target..."
resolve_device
adb -s "$SERIAL" uninstall "$PACKAGE" >/dev/null 2>&1 || true
adb -s "$SERIAL" install "$OUTPUT_APK" >/dev/null 2>&1 ||
  die "Install gagal pada $SERIAL"
launch_frida
