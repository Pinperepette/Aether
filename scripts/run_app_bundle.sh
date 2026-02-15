#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET_ARCH=""
SIGN_IDENTITY="${RUN_APP_SIGN_IDENTITY:--}"
EXTRA_ARGS=()

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options] [-- <extra build_dmg args>]

Builds Aether.app as a bundle (no DMG), then launches it.

Options:
  --arch <target>      arm64, x86_64, or universal
  --sign-identity <id> Override signing identity for local run (default: -)
  -h, --help           Show this help

Examples:
  scripts/run_app_bundle.sh
  scripts/run_app_bundle.sh --arch universal
  scripts/run_app_bundle.sh --sign-identity "Developer ID Application: Your Name (TEAMID)"
  scripts/run_app_bundle.sh -- --version 1.2.1
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)
      TARGET_ARCH="$2"
      shift 2
      ;;
    --sign-identity)
      SIGN_IDENTITY="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ -z "${TARGET_ARCH}" ]]; then
  host_arch="$(uname -m)"
  case "${host_arch}" in
    arm64|x86_64)
      TARGET_ARCH="${host_arch}"
      ;;
    *)
      TARGET_ARCH="universal"
      ;;
  esac
fi

cd "${ROOT_DIR}"
APP_SIGN_IDENTITY="${SIGN_IDENTITY}" \
  "${SCRIPT_DIR}/build_dmg.sh" \
  --app-only \
  --open-app \
  --arch "${TARGET_ARCH}" \
  "${EXTRA_ARGS[@]}"
