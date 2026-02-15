#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Aether"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
WORK_DIR="${ROOT_DIR}/.build/release-dmg"
DMG_STAGE_DIR="${WORK_DIR}/dmg-stage"
PROJECT_RESOURCES_DIR="${ROOT_DIR}/Sources/Aether/Resources"

APP_SIGN_IDENTITY="${APP_SIGN_IDENTITY:-}"
NOTARY_PROFILE="${NOTARY_PROFILE:-}"
SKIP_NOTARIZATION="${SKIP_NOTARIZATION:-0}"
TARGET_ARCH="${TARGET_ARCH:-universal}"
BUNDLE_ID="${BUNDLE_ID:-com.aether.app}"
APP_VERSION="${APP_VERSION:-}"
APP_BUILD="${APP_BUILD:-}"
BUILD_TIMESTAMP="${BUILD_TIMESTAMP:-}"
BUILD_COMMIT="${BUILD_COMMIT:-}"
LICENSE_NAME="${LICENSE_NAME:-MIT License}"
MIN_MACOS_VERSION="${MIN_MACOS_VERSION:-14.0}"
DMG_VOLUME_NAME="${DMG_VOLUME_NAME:-Aether}"
APP_ONLY="${APP_ONLY:-0}"
OPEN_APP="${OPEN_APP:-0}"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Builds Aether.app and by default also signs/notarizes/outputs dist/Aether-<arch>.dmg.

Options:
  --version <semver>        App version (default: latest git tag or 0.0.0)
  --arch <target>           universal (default), arm64, x86_64
  --bundle-id <id>          Bundle identifier (default: com.aether.app)
  --app-only                Build/sign app bundle only (no DMG/notarization)
  --open-app                Open resulting app bundle when done
  --skip-notarization       Skip notarization/stapling
  -h, --help                Show this help

Required env vars (unless --app-only is used):
  APP_SIGN_IDENTITY         Developer ID Application identity for codesign

Required unless --skip-notarization is used:
  NOTARY_PROFILE            Keychain profile configured via xcrun notarytool store-credentials

Optional env vars:
  APP_VERSION               Same as --version
  APP_BUILD                 CFBundleVersion (default: git short hash, fallback APP_VERSION)
  BUILD_TIMESTAMP           ISO8601 UTC timestamp (default: current UTC time)
  BUILD_COMMIT              Source revision marker (default: git short hash)
  LICENSE_NAME              License label shown in About window (default: MIT License)
  TARGET_ARCH               Same as --arch
  BUNDLE_ID                 Same as --bundle-id
  MIN_MACOS_VERSION         Defaults to 14.0
  DMG_VOLUME_NAME           Defaults to Aether
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      APP_VERSION="$2"
      shift 2
      ;;
    --arch)
      TARGET_ARCH="$2"
      shift 2
      ;;
    --bundle-id)
      BUNDLE_ID="$2"
      shift 2
      ;;
    --app-only)
      APP_ONLY=1
      shift
      ;;
    --open-app)
      OPEN_APP=1
      shift
      ;;
    --skip-notarization)
      SKIP_NOTARIZATION=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

generate_app_icon_icns() {
  local app_iconset_src="$1"
  local app_resources_dir="$2"
  local iconset_dir="${WORK_DIR}/AppIcon.iconset"
  local base_png="${app_iconset_src}/icon_1024.png"

  if [[ ! -d "${app_iconset_src}" ]]; then
    echo "Warning: App iconset not found at ${app_iconset_src}" >&2
    return 0
  fi

  if [[ ! -f "${base_png}" ]]; then
    base_png="$(find "${app_iconset_src}" -maxdepth 1 -type f -name '*.png' -print | head -n 1 || true)"
  fi

  if [[ -z "${base_png}" || ! -f "${base_png}" ]]; then
    echo "Warning: no PNG files found in ${app_iconset_src}" >&2
    return 0
  fi

  rm -rf "${iconset_dir}"
  mkdir -p "${iconset_dir}"

  sips -z 16 16 "${base_png}" --out "${iconset_dir}/icon_16x16.png" >/dev/null
  sips -z 32 32 "${base_png}" --out "${iconset_dir}/icon_16x16@2x.png" >/dev/null
  sips -z 32 32 "${base_png}" --out "${iconset_dir}/icon_32x32.png" >/dev/null
  sips -z 64 64 "${base_png}" --out "${iconset_dir}/icon_32x32@2x.png" >/dev/null
  sips -z 128 128 "${base_png}" --out "${iconset_dir}/icon_128x128.png" >/dev/null
  sips -z 256 256 "${base_png}" --out "${iconset_dir}/icon_128x128@2x.png" >/dev/null
  sips -z 256 256 "${base_png}" --out "${iconset_dir}/icon_256x256.png" >/dev/null
  sips -z 512 512 "${base_png}" --out "${iconset_dir}/icon_256x256@2x.png" >/dev/null
  sips -z 512 512 "${base_png}" --out "${iconset_dir}/icon_512x512.png" >/dev/null
  cp "${base_png}" "${iconset_dir}/icon_512x512@2x.png"

  iconutil -c icns "${iconset_dir}" -o "${app_resources_dir}/AppIcon.icns"
}

log() {
  printf '\n[%s] %s\n' "$(date +'%H:%M:%S')" "$*"
}

resolve_release_dir() {
  local arch="$1"
  local path

  path="$(find "${ROOT_DIR}/.build" -type d -path "*/${arch}-apple-macosx*/release" -print | head -n 1 || true)"
  if [[ -z "${path}" ]]; then
    echo "Could not locate release directory for architecture: ${arch}" >&2
    return 1
  fi

  printf '%s\n' "${path}"
}

if [[ "${APP_ONLY}" == "1" ]]; then
  SKIP_NOTARIZATION=1
fi

if [[ -z "${APP_SIGN_IDENTITY}" ]]; then
  if [[ "${APP_ONLY}" == "1" ]]; then
    APP_SIGN_IDENTITY="-"
  else
    echo "APP_SIGN_IDENTITY is required." >&2
    exit 1
  fi
fi

if [[ "${TARGET_ARCH}" != "universal" && "${TARGET_ARCH}" != "arm64" && "${TARGET_ARCH}" != "x86_64" ]]; then
  echo "Invalid --arch value: ${TARGET_ARCH}. Expected one of: universal, arm64, x86_64" >&2
  exit 1
fi

if [[ "${SKIP_NOTARIZATION}" != "1" && -z "${NOTARY_PROFILE}" ]]; then
  echo "NOTARY_PROFILE is required unless --skip-notarization is used." >&2
  exit 1
fi

if [[ -z "${APP_VERSION}" ]]; then
  APP_VERSION="$(git -C "${ROOT_DIR}" describe --tags --abbrev=0 2>/dev/null || true)"
  APP_VERSION="${APP_VERSION#v}"
fi

if [[ -z "${APP_VERSION}" ]]; then
  APP_VERSION="0.0.0"
fi

if [[ -z "${APP_BUILD}" ]]; then
  APP_BUILD="$(git -C "${ROOT_DIR}" rev-parse --short=8 HEAD 2>/dev/null || true)"
fi

if [[ -z "${APP_BUILD}" ]]; then
  APP_BUILD="${APP_VERSION}"
fi

if [[ -z "${BUILD_TIMESTAMP}" ]]; then
  BUILD_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
fi

if [[ -z "${BUILD_COMMIT}" ]]; then
  BUILD_COMMIT="$(git -C "${ROOT_DIR}" rev-parse --short=12 HEAD 2>/dev/null || true)"
fi

if [[ -z "${BUILD_COMMIT}" ]]; then
  BUILD_COMMIT="${APP_BUILD}"
fi

require_cmd swift
require_cmd lipo
require_cmd codesign
require_cmd sips
require_cmd iconutil
if [[ "${APP_ONLY}" != "1" ]]; then
  require_cmd hdiutil
fi
if [[ "${SKIP_NOTARIZATION}" != "1" ]]; then
  require_cmd ditto
  require_cmd xcrun
fi
if [[ "${OPEN_APP}" == "1" ]]; then
  require_cmd open
fi

log "Cleaning previous artifacts"
rm -rf "${WORK_DIR}" "${DIST_DIR}"
mkdir -p "${WORK_DIR}" "${DIST_DIR}"

log "Build metadata: version=${APP_VERSION}, build=${APP_BUILD}, commit=${BUILD_COMMIT}, arch=${TARGET_ARCH}"

APP_DIR="${WORK_DIR}/${APP_NAME}.app"
mkdir -p "${APP_DIR}/Contents/MacOS" "${APP_DIR}/Contents/Resources"

RESOURCE_RELEASE_DIR=""
if [[ "${TARGET_ARCH}" == "universal" ]]; then
  log "Building release binaries (arm64 + x86_64)"
  swift build --package-path "${ROOT_DIR}" -c release --arch arm64
  swift build --package-path "${ROOT_DIR}" -c release --arch x86_64

  ARM_RELEASE_DIR="$(resolve_release_dir arm64)"
  X86_RELEASE_DIR="$(resolve_release_dir x86_64)"
  ARM_BINARY="${ARM_RELEASE_DIR}/${APP_NAME}"
  X86_BINARY="${X86_RELEASE_DIR}/${APP_NAME}"

  if [[ ! -f "${ARM_BINARY}" ]]; then
    echo "Missing arm64 binary: ${ARM_BINARY}" >&2
    exit 1
  fi

  if [[ ! -f "${X86_BINARY}" ]]; then
    echo "Missing x86_64 binary: ${X86_BINARY}" >&2
    exit 1
  fi

  log "Creating universal executable"
  lipo -create "${ARM_BINARY}" "${X86_BINARY}" -output "${APP_DIR}/Contents/MacOS/${APP_NAME}"
  RESOURCE_RELEASE_DIR="${ARM_RELEASE_DIR}"
else
  log "Building release binary (${TARGET_ARCH})"
  swift build --package-path "${ROOT_DIR}" -c release --arch "${TARGET_ARCH}"
  RELEASE_DIR="$(resolve_release_dir "${TARGET_ARCH}")"
  ARCH_BINARY="${RELEASE_DIR}/${APP_NAME}"

  if [[ ! -f "${ARCH_BINARY}" ]]; then
    echo "Missing ${TARGET_ARCH} binary: ${ARCH_BINARY}" >&2
    exit 1
  fi

  cp "${ARCH_BINARY}" "${APP_DIR}/Contents/MacOS/${APP_NAME}"
  RESOURCE_RELEASE_DIR="${RELEASE_DIR}"
fi

chmod 755 "${APP_DIR}/Contents/MacOS/${APP_NAME}"

log "Copying SwiftPM resource bundles"
found_bundle=0
while IFS= read -r -d '' bundle_path; do
  cp -R "${bundle_path}" "${APP_DIR}/Contents/Resources/"
  found_bundle=1
done < <(find "${RESOURCE_RELEASE_DIR}" -maxdepth 1 -type d -name "*.bundle" -print0)

if [[ "${found_bundle}" -eq 0 ]]; then
  echo "Warning: no .bundle resources found in ${RESOURCE_RELEASE_DIR}" >&2
fi

if [[ -d "${PROJECT_RESOURCES_DIR}" ]]; then
  log "Copying source resources from ${PROJECT_RESOURCES_DIR}"
  mkdir -p "${APP_DIR}/Contents/Resources/AetherResources"
  cp -R "${PROJECT_RESOURCES_DIR}/." "${APP_DIR}/Contents/Resources/AetherResources/"
fi

if [[ -f "${ROOT_DIR}/LICENSE" ]]; then
  cp "${ROOT_DIR}/LICENSE" "${APP_DIR}/Contents/Resources/LICENSE.txt"
fi

log "Generating AppIcon.icns from source iconset (if available)"
generate_app_icon_icns \
  "${PROJECT_RESOURCES_DIR}/Assets.xcassets/AppIcon.appiconset" \
  "${APP_DIR}/Contents/Resources"

log "Writing Info.plist"
cat > "${APP_DIR}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>${BUNDLE_ID}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleShortVersionString</key>
  <string>${APP_VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${APP_BUILD}</string>
  <key>AetherBuildTimestamp</key>
  <string>${BUILD_TIMESTAMP}</string>
  <key>AetherBuildTargetArch</key>
  <string>${TARGET_ARCH}</string>
  <key>AetherBuildCommit</key>
  <string>${BUILD_COMMIT}</string>
  <key>AetherLicense</key>
  <string>${LICENSE_NAME}</string>
  <key>LSMinimumSystemVersion</key>
  <string>${MIN_MACOS_VERSION}</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

log "Signing app bundle"
if [[ "${APP_ONLY}" == "1" ]]; then
  # Local run path: avoid timestamp/runtime requirements that can block on keychain/network.
  codesign --force --sign "${APP_SIGN_IDENTITY}" "${APP_DIR}"
else
  codesign --force --timestamp --options runtime --sign "${APP_SIGN_IDENTITY}" "${APP_DIR}"
fi
codesign --verify --deep --strict --verbose=2 "${APP_DIR}"

if [[ "${SKIP_NOTARIZATION}" != "1" ]]; then
  APP_ZIP="${WORK_DIR}/${APP_NAME}.zip"
  log "Creating zip for app notarization"
  ditto -c -k --keepParent "${APP_DIR}" "${APP_ZIP}"

  log "Submitting app for notarization"
  xcrun notarytool submit "${APP_ZIP}" --keychain-profile "${NOTARY_PROFILE}" --wait

  log "Stapling notarization ticket to app"
  xcrun stapler staple "${APP_DIR}"
  xcrun stapler validate "${APP_DIR}"
fi

FINAL_APP="${DIST_DIR}/${APP_NAME}-${TARGET_ARCH}.app"
rm -rf "${FINAL_APP}"
cp -R "${APP_DIR}" "${FINAL_APP}"

APP_EXEC_SHA256="$(shasum -a 256 "${APP_DIR}/Contents/MacOS/${APP_NAME}" | awk '{print $1}')"
APP_SHA_FILE="${DIST_DIR}/${APP_NAME}-${TARGET_ARCH}.app-executable.sha256"
printf '%s  %s\n' "${APP_EXEC_SHA256}" "${APP_NAME}.app/Contents/MacOS/${APP_NAME}" > "${APP_SHA_FILE}"

if [[ "${APP_ONLY}" == "1" ]]; then
  MANIFEST_FILE="${DIST_DIR}/${APP_NAME}-${TARGET_ARCH}.build-manifest.json"
  cat > "${MANIFEST_FILE}" <<JSON
{
  "app_name": "${APP_NAME}",
  "bundle_id": "${BUNDLE_ID}",
  "version": "${APP_VERSION}",
  "build": "${APP_BUILD}",
  "build_timestamp_utc": "${BUILD_TIMESTAMP}",
  "build_commit": "${BUILD_COMMIT}",
  "target_arch": "${TARGET_ARCH}",
  "license": "${LICENSE_NAME}",
  "app_bundle": "$(basename "${FINAL_APP}")",
  "app_executable_sha256": "${APP_EXEC_SHA256}"
}
JSON

  log "Done"
  echo "App: ${FINAL_APP}"
  echo "App executable SHA256: ${APP_EXEC_SHA256}"
  echo "Checksum file: ${APP_SHA_FILE}"
  echo "Manifest: ${MANIFEST_FILE}"
  if [[ "${OPEN_APP}" == "1" ]]; then
    open "${FINAL_APP}"
    echo "Opened: ${FINAL_APP}"
  fi
  exit 0
fi

log "Preparing DMG staging folder"
rm -rf "${DMG_STAGE_DIR}"
mkdir -p "${DMG_STAGE_DIR}"
cp -R "${APP_DIR}" "${DMG_STAGE_DIR}/"
ln -s /Applications "${DMG_STAGE_DIR}/Applications"

UNSIGNED_DMG="${WORK_DIR}/${APP_NAME}.dmg"
FINAL_DMG="${DIST_DIR}/${APP_NAME}-${TARGET_ARCH}.dmg"

log "Building DMG"
hdiutil create \
  -volname "${DMG_VOLUME_NAME}" \
  -srcfolder "${DMG_STAGE_DIR}" \
  -format UDZO \
  -fs HFS+ \
  "${UNSIGNED_DMG}"

log "Signing DMG"
codesign --force --timestamp --sign "${APP_SIGN_IDENTITY}" "${UNSIGNED_DMG}"
codesign --verify --verbose=2 "${UNSIGNED_DMG}"

if [[ "${SKIP_NOTARIZATION}" != "1" ]]; then
  log "Submitting DMG for notarization"
  xcrun notarytool submit "${UNSIGNED_DMG}" --keychain-profile "${NOTARY_PROFILE}" --wait

  log "Stapling notarization ticket to DMG"
  xcrun stapler staple "${UNSIGNED_DMG}"
  xcrun stapler validate "${UNSIGNED_DMG}"
fi

mv -f "${UNSIGNED_DMG}" "${FINAL_DMG}"
DMG_SHA256="$(shasum -a 256 "${FINAL_DMG}" | awk '{print $1}')"
DMG_SHA_FILE="${FINAL_DMG}.sha256"
MANIFEST_FILE="${DIST_DIR}/${APP_NAME}-${TARGET_ARCH}.build-manifest.json"

printf '%s  %s\n' "${APP_EXEC_SHA256}" "${APP_NAME}.app/Contents/MacOS/${APP_NAME}" > "${APP_SHA_FILE}"
printf '%s  %s\n' "${DMG_SHA256}" "$(basename "${FINAL_DMG}")" > "${DMG_SHA_FILE}"

cat > "${MANIFEST_FILE}" <<JSON
{
  "app_name": "${APP_NAME}",
  "bundle_id": "${BUNDLE_ID}",
  "version": "${APP_VERSION}",
  "build": "${APP_BUILD}",
  "build_timestamp_utc": "${BUILD_TIMESTAMP}",
  "build_commit": "${BUILD_COMMIT}",
  "target_arch": "${TARGET_ARCH}",
  "license": "${LICENSE_NAME}",
  "app_executable_sha256": "${APP_EXEC_SHA256}",
  "dmg_file": "$(basename "${FINAL_DMG}")",
  "dmg_sha256": "${DMG_SHA256}"
}
JSON

log "Done"
echo "DMG: ${FINAL_DMG}"
echo "DMG SHA256: ${DMG_SHA256}"
echo "App executable SHA256: ${APP_EXEC_SHA256}"
echo "Checksum file: ${DMG_SHA_FILE}"
echo "Checksum file: ${APP_SHA_FILE}"
echo "Manifest: ${MANIFEST_FILE}"
