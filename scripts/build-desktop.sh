#!/bin/zsh
set -euo pipefail

SCRIPT_DIR=${0:A:h}
PROJECT_ROOT=${SCRIPT_DIR:h}
BINARY="$PROJECT_ROOT/target/release/Apiary"
IDENTIFIER=wine.wisco.apiary

cd "$PROJECT_ROOT"
cargo build -p apiary-desktop --release

if [[ $(uname -s) != Darwin ]]; then
  print "Built $BINARY"
  exit 0
fi

# A linker-generated ad-hoc signature is different after every build. macOS
# Keychain therefore treats each development build as a new application and
# asks again. Prefer an explicit identity, otherwise select a stable local
# code-signing certificate without hard-coding one developer's name.
IDENTITY=${APIARY_CODESIGN_IDENTITY:-}
if [[ -z "$IDENTITY" ]]; then
  IDENTITY=$(/usr/bin/security find-identity -v -p codesigning \
    | /usr/bin/awk -F'"' '/Developer ID Application/ { print $2; exit }')
fi
if [[ -z "$IDENTITY" ]]; then
  IDENTITY=$(/usr/bin/security find-identity -v -p codesigning \
    | /usr/bin/awk -F'"' '/Apple Development/ && $0 !~ /REVOKED/ { print $2; exit }')
fi
if [[ -z "$IDENTITY" ]]; then
  print -u2 "Built $BINARY, but no valid code-signing identity was found."
  print -u2 "Keychain may ask again after the next rebuild. Set APIARY_CODESIGN_IDENTITY to a stable identity."
  exit 0
fi

/usr/bin/codesign \
  --force \
  --sign "$IDENTITY" \
  --identifier "$IDENTIFIER" \
  --options runtime \
  --timestamp=none \
  "$BINARY"
/usr/bin/codesign --verify --strict --verbose=2 "$BINARY"
print "Built and signed $BINARY as $IDENTIFIER with $IDENTITY"
