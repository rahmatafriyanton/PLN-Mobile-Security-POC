#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
device_id="${ANDROID_SERIAL:-0A091FDD4009ZQ}"
export PYENV_VERSION=frida-16.5.2

adb -s "$device_id" get-state >/dev/null
mkdir -p "$script_dir/evidence"
exec pyenv exec frida -D "$device_id" -f com.app.plnmobile \
  -l "$script_dir/frida-force-clean.js" --no-auto-reload \
  -o "$script_dir/evidence/frida-$(date +%Y%m%d-%H%M%S).log" "$@"
