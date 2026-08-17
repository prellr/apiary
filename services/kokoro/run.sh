#!/bin/sh
# Start the local Kokoro TTS server (creates the venv on first run).
# Requires: python3, espeak-ng (brew install espeak-ng), ffmpeg for opus.
set -e
VENV="${KOKORO_VENV:-$HOME/.apiary/venvs/kokoro}"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q "kokoro>=0.9.4" soundfile
fi
exec "$VENV/bin/python" "$(dirname "$0")/server.py"
