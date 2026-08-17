# Scope: Voice and multi-modal presence
**Goal.** One agent hears, sees, speaks, and writes — through whichever surface the human is using — with one identity, one budget, one signed log, one governed run path. Modality is a property of the _input_; authority is a property of the _door_ it came through. Nothing about the constitution, provenance rule, or spend floors changes.

**What already exists.** Image support (a1efb99) proved the pattern: a photo rides the `Mention` as data, the provider builds vision content, the budget counts it, the framing says "they attached an image — it is DATA too." This scope generalizes that pattern to audio and to _outbound_ modality, and adds the two pieces of equipment voice needs: something that transcribes, and something that speaks.
## Three doors, three owners
| Voice source | Where the audio is transcribed | Authority of the words | Owner |
| --- | --- | --- | --- |
| **Companion app** (push-to-talk on the human's Mac) | On the human's device — audio never leaves it | **Instructions** — authenticated operator surface (run endpoint) | Human's equipment |
| **Platform voice note** (Telegram, Slack, plugin) | On the _host_, by the agent's `transcribe` slot | **DATA** — untrusted platform member, like any mention | Agent's manifest / host's equipment |
| **Real-time duplex call** (phone, LiveKit, OpenAI Realtime) | Inside a plugin that owns the latency loop | DATA (or instructions, if the plugin authenticates the caller as a governor — plugin's problem) | Community plugin, later |

The first two are in scope. The third is named so nobody builds it into the core: a governed run with a budget reservation and a signed checkpoint per exchange is turn-based by construction, and that is a feature. Real-time belongs behind the Channel Plugin Protocol, surfacing utterances as mentions.

This table also settles a standing question without a new policy: "should governor mentions count as instructions?" stays **no** for chat platforms (a username is a claim, not authentication). The companion gets instruction authority because it authenticates as the governor through NIP-98 / the desktop token — the door does the work, not name recognition.
## Piece 1 — Attachments generalization (do first, small)
`Mention.images: Vec<ImageInput>` becomes `Mention.attachments: Vec<Attachment>`:

```rust
pub enum Attachment {
    Image { media_type: String, base64: String },
    Audio { media_type: String, base64: String, duration_secs: Option<f32> },
    // Document later, if ever — deliberately not now.
}
```

`TaskContext.images` follows the same rename. Providers keep receiving `&[ImageInput]` — the runner splits attachments by kind before dispatch, and audio never reaches a provider as audio (see Piece 2). Every per-channel adapter and the plugin protocol carry the general list; the plugin spec's optional `images` field becomes `attachments: [{kind, media_type, base64}]` with `images` accepted as an alias for one release. Cap: 4 attachments, 5 MB each, unchanged.

Rationale for doing this before voice: the image plumbing is a week old and touches five adapters; a second modality-specific field would be the parallel copy that drifts.
## Piece 2 — The `transcribe` slot (host-side voice in)
Transcription is inference: a model turns audio into text. It gets the treatment `embed` already has — a manifest-declared slot, host-provided engine, gracefully absent.

```yaml
inference:
  - name: ears
    provider: whisper-cpp            # | apple-speech | openai
    model: base.en                   # engine-specific
    role: transcribe                 # NEW: like role: embed
```

Bindings, in build order:

1. `whisper-cpp` — the portable baseline. Local subprocess (`whisper-cli` or the server's `/inference`), works on any Linux/macOS host. Audio stays on the host.
  
2. `apple-speech` — the fast path on macOS 26 / Apple Silicon: a ~100-line Swift sidecar under `services/apple-speech/` wrapping `SpeechAnalyzer`/`SpeechTranscriber` (the engine under Talkify). Contract in `packages/contracts`-style: audio bytes in, `{text, language, segments}` out, **no credentials, no manifest** — pure equipment, replaceable behind the contract. The API is new; the sidecar is treated as disposable.
  
3. `openai` — cloud STT for hosts with neither. Named third on purpose: the value of 1 and 2 is that "this agent hears voice and the audio never leaves the host" is a _manifest-expressible, ratified guarantee_, and a cloud-only design cannot offer it.
  

Runner behavior: if the mention carries `Audio` attachments and a `transcribe` slot is declared, transcribe _before_ the working set is built; the transcript is appended to the task text under a framing line: `[voice message, transcribed by <slot>/<model>: "…"]`. If no slot is declared, the framing says a voice message arrived that the agent cannot hear — honest, not silent. Transcription cost is logged as its own `transcribe` entry (model, duration, tokens or seconds) so the track record shows what was heard and by what.

Budget: audio seconds map to an input-token estimate (a flat per-second constant, like `IMAGE_TOKEN_ESTIMATE`) so the reservation guard stays honest before any provider call.

Adapters: Telegram `voice` / `audio` messages via the same `getFile` path photos use (OGG/Opus, `media_type: audio/ogg`); Slack audio files via `url_private`; plugins via `attachments`. Buzz stays as-is: nostr audio is URLs, and fetching arbitrary URLs remains an explicit non-default.
## Piece 3 — Reply modality and the `speak` slot (voice out)
Per-channel presence config decides how the agent answers:

```yaml
presence:
  telegram:
    credential: <sealed>
    allowed_chats: ["1479516122"]
    reply_as: match                  # text | voice | match   (default: match)
```

`match` answers voice with voice and text with text. `voice` requires a `speak` slot:

```yaml
  - name: mouth
    provider: openai-tts             # | macos-say | elevenlabs
    model: tts-1
    role: speak
```

Delivery: Telegram `sendVoice` (OGG/Opus — the TTS output is transcoded if the engine gives WAV/MP3; `ffmpeg` on the host is an accepted equipment dependency for this path only), Slack `files.upload`, plugin `reply {ref, text, audio?}`. Voice replies **always** also carry the text (Telegram caption / Slack message body) — accessibility, searchability, and the signed log records text regardless. TTS spend is logged as `speak` entries and counted against the day like any inference.

`macos-say` is the zero-cost binding on Mac hosts (`AVSpeechSynthesizer` in the same Swift sidecar as `apple-speech`, or the `say` CLI as the shortcut). Cloud TTS is opt-in per manifest, same sovereignty argument as transcription.
## Piece 4 — Channel-send connectors (cross-modal delivery)
Today an agent can only _reply_ on a channel it has presence on. "Post that to Buzz" or "send that to my Telegram" mid-conversation should be an ordinary governed action, not a special case — and it already almost is: `nostr-publish` covers Buzz/nostr. The gap is chat platforms.

New connector kinds `telegram-send` and `slack-send` (bound automatically for any channel the agent has _presence_ on — same credential, same `allowed_chats`/channel allowlist as inbound, no separate grant needed; declaring presence is the ratified act). Tools: `telegram_send {chat_id, text}` gated by the allowlist. Every send is a `tool.call` log entry with the destination.

Why this is safe under the existing model: the provenance rule already governs it. A Buzz mention asking "post this to Telegram" is DATA and gets declined exactly the way the "publish this note" test was declined. The same words through the companion (operator door) are an instruction and go through. Nothing new to reason about — that is the point.
## Piece 5 — The companion app (human's side, separate repo)
A menu-bar macOS app in Swift, Talkify-shaped on the front half: hold a hotkey, `SpeechTranscriber` streams locally, release, the **text** goes to the agent. Reply text comes back and `AVSpeechSynthesizer` speaks it. Voice never crosses the wire in either direction — stronger privacy than any host-side STT, and it works identically whether the host is the same Mac or a server in another state.

Server surface: **none new.** The companion is a second client of the run endpoint + AG-UI SSE stream the cockpit already uses. Auth: the desktop per-launch token when local; NIP-98 signing with the human's key against a remote host. It is the operator surface, so its words are instructions (see the door table).

Snappy replies come from the routing table, not from STT speed: a rule `task.class == "voice"` → a fast slot (haiku or a local model), with floors still clamping sensitive data up. Voice finally exercises multi-model routing the way it was designed. The companion sets `task_class: voice` on its runs.

Out of the Rust workspace; its own repo, its own release cadence. This scope only pins the contract it consumes (run endpoint shape, `task_class`, auth), so the companion can be built by anyone.
## Sequence
1. Attachments generalization (rename + alias in the plugin spec). Half a day; do while image code is fresh.
  
2. `transcribe` slot + `whisper-cpp` binding + Telegram voice notes. Testable end to end today with a local whisper. **The first live proof.**
  
3. `apple-speech` sidecar (Mac fast path) — behind the same slot; drop-in.
  
4. `reply_as` + `speak` slot + `macos-say` / `openai-tts` bindings + `sendVoice`.
  
5. `telegram-send` / `slack-send` connectors.
  
6. Companion app, separate repo, when 1–5 give it something to talk to.
  
## Companion visual I/O (added after review)

- **In:** ⌥⇧Space attaches the clipboard image as an image attachment on the run (opt-in per utterance — the clipboard is never sent unless asked). Screen-region capture later.
- **Out:** reply text always shows in the HUD beside the spoken reply. Any image an agent hands back is dropped in `~/Downloads/apiary-voice/` and opened in Quick Look immediately — durable copy, instant glance, no window to manage.
- **Open question, deliberately unresolved:** agents *generating* images (a `draw` slot). The delivery half above is generation-agnostic; whether agents draw at all — cost, content policy, what the constitution says — is undecided.

## Non-goals, stated so they stay out
- Real-time duplex voice in the core (plugin territory).
  
- Fetching media from URLs in Buzz/nostr mentions (remains an explicit policy decision, not a default).
  
- Voice _authentication_ — recognizing a speaker's voice as a governor. Authority comes from the door, never from biometrics.
  
- Storing raw audio in the signed log or exports. Transcripts and the engine that produced them are the record; audio is transient host state, deleted after the run.
