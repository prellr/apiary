#!/usr/bin/env python3
"""apiary kokoro — a local text-to-speech server around Kokoro-82M.

Speaks the OpenAI `/v1/audio/speech` shape on 127.0.0.1 so it plugs into
Apiary's `speak` slot as `provider: openai` + `requires.base_url` (keyless,
like the ollama /v1 inference slot), and so apiary-voice can use the same
voice locally. The model loads once and stays resident (~300 MB); each
request is a forward pass on the M-series GPU (MPS) or CPU.

    POST /v1/audio/speech  {"input": "...", "voice": "af_heart", "speed": 1.0,
                             "response_format": "wav"|"opus"}
      → audio bytes (audio/wav or audio/ogg)
    GET  /v1/audio/voices  → {"voices": [...]}
    GET  /health           → {"ok": true, "model": "kokoro-82M", "device": "mps"}

Sidecar rule: contracts, not credentials — text in, audio out, no keys.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.environ.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "1")

import numpy as np  # noqa: E402
import soundfile as sf  # noqa: E402
import torch  # noqa: E402
from kokoro import KPipeline  # noqa: E402

SAMPLE_RATE = 24000
DEVICE = "mps" if torch.backends.mps.is_available() else "cpu"
LANG = {"a": "American English", "b": "British English"}
_pipelines = {}
_lock = threading.Lock()

# Kokoro v1.0 voice ids (prefix: a=American, b=British; f/m = female/male).
VOICES = [
    "af_heart", "af_alloy", "af_aoede", "af_bella", "af_jessica", "af_kore",
    "af_nicole", "af_nova", "af_river", "af_sarah", "af_sky",
    "am_adam", "am_echo", "am_eric", "am_fenrir", "am_liam", "am_michael",
    "am_onyx", "am_puck", "am_santa",
    "bf_alice", "bf_emma", "bf_isabella", "bf_lily",
    "bm_daniel", "bm_fable", "bm_george", "bm_lewis",
]


def pipeline(lang_code):
    with _lock:
        if lang_code not in _pipelines:
            _pipelines[lang_code] = KPipeline(lang_code=lang_code, repo_id="hexgrad/Kokoro-82M", device=DEVICE)
        return _pipelines[lang_code]


def synthesize(text, voice, speed):
    lang = voice[0] if voice[:1] in LANG else "a"
    pipe = pipeline(lang)
    chunks = []
    for _, _, audio in pipe(text, voice=voice, speed=speed):
        chunks.append(audio.detach().cpu().numpy() if hasattr(audio, "detach") else np.asarray(audio))
    if not chunks:
        return np.zeros(0, dtype=np.float32)
    return np.concatenate(chunks).astype(np.float32)


def to_wav(pcm):
    buf = io.BytesIO()
    sf.write(buf, pcm, SAMPLE_RATE, format="WAV", subtype="PCM_16")
    return buf.getvalue()


def to_opus(pcm):
    """OGG/Opus via ffmpeg (Telegram voice notes)."""
    with tempfile.TemporaryDirectory() as d:
        wav = os.path.join(d, "in.wav")
        ogg = os.path.join(d, "out.ogg")
        sf.write(wav, pcm, SAMPLE_RATE, format="WAV", subtype="PCM_16")
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", wav, "-c:a", "libopus",
                        "-b:a", "32k", "-application", "voip", "-f", "ogg", ogg], check=True)
        with open(ogg, "rb") as f:
            return f.read()


class Handler(BaseHTTPRequestHandler):
    server_version = "apiary-kokoro/0.1"

    def log_message(self, fmt, *args):  # quiet; stderr is for real problems
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"ok": True, "model": "kokoro-82M", "device": DEVICE, "sample_rate": SAMPLE_RATE})
        if self.path.startswith("/v1/audio/voices"):
            return self._json(200, {"voices": VOICES})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/audio/speech":
            return self._json(404, {"error": "not found"})
        try:
            n = int(self.headers.get("content-length", "0"))
            req = json.loads(self.rfile.read(n) or b"{}")
            text = (req.get("input") or "").strip()
            if not text:
                return self._json(400, {"error": "input required"})
            voice = req.get("voice") or "af_heart"
            speed = float(req.get("speed") or 1.0)
            fmt = (req.get("response_format") or "wav").lower()
            pcm = synthesize(text[:5000], voice, speed)
            if fmt in ("opus", "ogg"):
                body, ctype = to_opus(pcm), "audio/ogg"
            else:
                body, ctype = to_wav(pcm), "audio/wav"
            self.send_response(200)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(body)))
            self.send_header("x-duration-secs", f"{len(pcm) / SAMPLE_RATE:.2f}")
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:  # noqa: BLE001
            print(f"speech error: {e}", file=sys.stderr)
            self._json(500, {"error": str(e)})


def main():
    port = int(os.environ.get("KOKORO_PORT", "8880"))
    print(f"apiary-kokoro: loading Kokoro-82M on {DEVICE}…", file=sys.stderr)
    pipeline("a")  # warm: download weights on first run, load once
    print(f"apiary-kokoro: listening on http://127.0.0.1:{port}/v1", file=sys.stderr)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
