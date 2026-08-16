# services/ — host equipment sidecars

Non-Rust components the host *may* have. Each is a standalone executable
speaking a small stdio JSON contract. The rule that makes them safe to
install is the same one Framework uses for its sidecars:

**Sidecars get contracts, not credentials.** A sidecar receives exactly the
bytes it needs to do its one job (audio in, text out) and nothing else — no
keystore, no manifest, no agent material, no network access required. The
runtime spawns them with a scrubbed environment (`PATH`, `HOME`, `TMPDIR`)
and treats them as replaceable equipment behind a manifest slot: an agent
declares *what* it needs (`transcribe`), the host decides *which* engine
provides it. Migrate the agent to a host without the sidecar and the slot
binds to another engine — the agent doesn't know or care.

## apple-speech (macOS 26+, Apple Silicon)

The Mac host's ears and mouth: Apple's on-device `SpeechTranscriber` for
speech-to-text and `AVSpeechSynthesizer` for text-to-speech. Audio never
leaves the machine; no model download beyond Apple's one-time on-device
asset install. On the same 4-second OGG/Opus voice note this ran ~7× faster
than whisper.cpp `base.en` (1.3s vs 9.8s).

Build and install:

```bash
cd services/apple-speech && swift build -c release
mkdir -p ~/.apiary/bin && cp .build/release/apple-speech ~/.apiary/bin/
```

The runtime finds it at `requires.command`, `$APIARY_APPLE_SPEECH`,
`~/.apiary/bin/apple-speech`, `/usr/local/bin/apple-speech`, or
`/opt/homebrew/bin/apple-speech` — first hit wins.

Declare it in a manifest:

```yaml
inference:
  - name: transcribe
    provider: apple-speech        # whisper-cpp on non-Mac hosts
    requires:
      locale: en-US               # optional; default en-US
```

Contract (one JSON object per line on stdin, one per line on stdout):

| op | request | response |
| --- | --- | --- |
| `probe` | `{"op":"probe"}` | `{"ok":true,"transcribe":bool,"speak":true,"locales":[…]}` |
| `transcribe` | `{"op":"transcribe","audio_b64":…,"media_type":"audio/ogg","locale"?:…}` | `{"ok":true,"text":…,"language":…,"duration_secs":…,"engine":…}` |
| `speak` | `{"op":"speak","text":…,"voice"?:…,"rate"?:0.5}` | `{"ok":true,"audio_b64":…,"media_type":"audio/x-caf","duration_secs":…,"engine":…}` |
| any | — | `{"ok":false,"error":…}` |

Any format AVFoundation opens is accepted natively (Telegram's OGG/Opus
included on macOS 26); anything else falls back to `ffmpeg` if present. Raw
audio touches disk only as a 0700 temp file, removed before the response.

Try it:

```bash
echo '{"op":"probe"}' | ~/.apiary/bin/apple-speech
```
