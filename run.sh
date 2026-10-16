#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 {appdome|nexilis|zimperium} [args...]" >&2
  exit 2
fi
shift

case "$TARGET" in
  appdome)
    exec "$SCRIPT_DIR/AppDome/run.sh" "$@"
    ;;
  nexilis)
    exec "$SCRIPT_DIR/Nexilis/run.sh" "$@"
    ;;
  zimperium)
    exec "$SCRIPT_DIR/Zimpe/run.sh" "$@"
    ;;
  *)
    echo "Target tidak dikenal: $TARGET" >&2
    echo "Gunakan: appdome, nexilis, atau zimperium" >&2
    exit 2
    ;;
esac
