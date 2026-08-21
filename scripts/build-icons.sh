#!/bin/zsh
set -euo pipefail

SCRIPT_DIR=${0:A:h}
PROJECT_ROOT=${SCRIPT_DIR:h}
SOURCE="$PROJECT_ROOT/crates/apiary-desktop/icons/icon.svg"
PNG="$PROJECT_ROOT/crates/apiary-desktop/icons/icon.png"
ICONSET="$PROJECT_ROOT/crates/apiary-desktop/icons/Apiary.iconset"
OUTPUT="$PROJECT_ROOT/crates/apiary-desktop/icons/icon.icns"

mkdir -p "$ICONSET"
sips -s format png "$SOURCE" --out "$PNG" >/dev/null

for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$PNG" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z "$double" "$double" "$PNG" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done

iconutil -c icns "$ICONSET" -o "$OUTPUT"
rm -rf "$ICONSET"
print "built $OUTPUT"
