#!/bin/zsh
set -euo pipefail

SCRIPT_DIR=${0:A:h}
PROJECT_ROOT=${SCRIPT_DIR:h}
DESKTOP_ROOT="$PROJECT_ROOT/crates/apiary-desktop"
APP="$PROJECT_ROOT/target/release/bundle/macos/Apiary.app"
VERSION=$(/usr/bin/awk -F'"' '/^version = / { print $2; exit }' "$PROJECT_ROOT/Cargo.toml")
case $(uname -m) in
  arm64) BUNDLE_ARCH=aarch64 ;;
  x86_64) BUNDLE_ARCH=x64 ;;
  *) print -u2 "Unsupported macOS architecture: $(uname -m)"; exit 1 ;;
esac
DMG="$PROJECT_ROOT/target/release/bundle/dmg/Apiary_${VERSION}_${BUNDLE_ARCH}.dmg"

if [[ $(uname -s) != Darwin ]]; then
  print -u2 "macOS packages must be built on macOS."
  exit 1
fi

if ! cargo tauri --version >/dev/null 2>&1; then
  print -u2 "Tauri CLI 2 is required. Install it with:"
  print -u2 "  cargo install tauri-cli --version '^2' --locked"
  exit 1
fi

# Direct-download releases require a Developer ID Application identity. Do not
# silently fall back to Apple Development: it cannot produce a distributable,
# notarized build.
IDENTITY=${APPLE_SIGNING_IDENTITY:-${APIARY_CODESIGN_IDENTITY:-}}
if [[ -z "$IDENTITY" ]]; then
  IDENTITY=$(/usr/bin/security find-identity -v -p codesigning \
    | /usr/bin/awk -F'"' '/Developer ID Application/ { print $2; exit }')
fi
if [[ -z "$IDENTITY" ]]; then
  print -u2 "No Developer ID Application identity was found."
  print -u2 "Install one or set APPLE_SIGNING_IDENTITY."
  exit 1
fi
export APPLE_SIGNING_IDENTITY="$IDENTITY"

# Tauri notarizes automatically when either supported credential set is
# present. Local bundle testing can opt out explicitly; production builds fail
# closed rather than accidentally publishing an unnotarized DMG.
HAS_API_KEY=false
if [[ -n ${APPLE_API_ISSUER:-} && -n ${APPLE_API_KEY:-} && -n ${APPLE_API_KEY_PATH:-} ]]; then
  HAS_API_KEY=true
fi
HAS_APPLE_ID=false
if [[ -n ${APPLE_ID:-} && -n ${APPLE_PASSWORD:-} && -n ${APPLE_TEAM_ID:-} ]]; then
  HAS_APPLE_ID=true
fi
SKIP_NOTARIZATION=${APIARY_SKIP_NOTARIZATION:-0}
if [[ "$SKIP_NOTARIZATION" != 1 && "$HAS_API_KEY" != true && "$HAS_APPLE_ID" != true ]]; then
  print -u2 "Notarization credentials are missing. Provide either:"
  print -u2 "  APPLE_API_ISSUER + APPLE_API_KEY + APPLE_API_KEY_PATH"
  print -u2 "or:"
  print -u2 "  APPLE_ID + APPLE_PASSWORD + APPLE_TEAM_ID"
  print -u2 "For a local-only packaging test, set APIARY_SKIP_NOTARIZATION=1."
  exit 1
fi

cd "$DESKTOP_ROOT"
cargo tauri build --bundles app,dmg

if [[ ! -d "$APP" ]]; then
  print -u2 "Expected app bundle was not produced at $APP"
  exit 1
fi
if [[ ! -f "$DMG" ]]; then
  print -u2 "Expected DMG was not produced at $DMG"
  exit 1
fi

/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP"
if [[ "$SKIP_NOTARIZATION" != 1 ]]; then
  /usr/sbin/spctl --assess --type execute --verbose=2 "$APP"
  /usr/bin/xcrun stapler validate "$APP"
  /usr/bin/xcrun stapler validate "$DMG"
fi

CHECKSUM="$DMG.sha256"
/usr/bin/shasum -a 256 "$DMG" > "$CHECKSUM"
print "App:      $APP"
print "DMG:      $DMG"
print "Checksum: $CHECKSUM"
