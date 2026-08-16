//! Transcription — the `transcribe` inference slot. Audio attached to a
//! task becomes text BEFORE the working set is built, so text providers
//! never see audio and the transcript is framed as DATA like the message
//! it arrived with.
//!
//! Same treatment as the `embed` slot: manifest-declared, host-provided
//! engine, gracefully absent (no slot → the run says a voice message
//! arrived that it cannot hear). Bindings, in order of preference:
//! - `apple-speech`: the macOS 26 fast path — Apple's on-device
//!   SpeechTranscriber via the `services/apple-speech` sidecar (~7× faster
//!   than whisper base.en on the same clip, no model download). Mac hosts
//!   only; audio never leaves the host.
//! - `whisper-cpp`: local subprocess, audio never leaves the host. The
//!   portable baseline (any Linux/macOS host); `model` is a ggml name/path.
//! - `openai`: `/audio/transcriptions` (Whisper API); `requires.base_url`
//!   redirects to any compatible endpoint. Cloud — opt in per manifest.
//! - `mock`: tests.
//!
//! Every binding takes bytes + media type and returns text; format
//! conversion (Telegram's OGG/Opus → 16 kHz WAV) is the binding's problem,
//! solved here with ffmpeg where needed. Raw audio is transient host
//! state: written to a temp file for the engine, deleted after.

use serde::Deserialize;
use std::path::PathBuf;
use std::process::Command;
use zeroize::Zeroizing;

/// Flat budget estimate: seconds of audio → input tokens. Coarse on
/// purpose (spoken English ~2.5 words/s ≈ 3.5 tokens/s; round up so the
/// reservation guard errs toward refusing, not overrunning).
pub const AUDIO_TOKENS_PER_SEC: u64 = 4;
/// When duration is unknown, assume this many seconds for the estimate.
pub const AUDIO_DEFAULT_SECS: u64 = 60;
/// Hard ceiling per clip — a 5 MB OGG can be an hour of speech; the day's
/// budget is not the only floor.
pub const MAX_AUDIO_SECS: f32 = 600.0;

#[derive(Debug, Clone)]
pub struct Transcript {
    pub text: String,
    pub engine: String,
    pub language: Option<String>,
    pub duration_secs: Option<f32>,
}

pub trait Transcriber {
    fn transcribe(&self, audio: &[u8], media_type: &str) -> Result<Transcript, crate::Error>;
    /// Identity string for the log ("whisper-cpp/base.en").
    fn id(&self) -> String;
}

/// Bind a transcriber from the manifest's `transcribe` slot, if declared.
/// `credential` is the JIT-decrypted slot credential (openai needs it).
pub fn bind_transcriber(
    manifest: &apiary_core::manifest::Manifest,
    credential: Option<Zeroizing<String>>,
) -> Option<Box<dyn Transcriber>> {
    let slot = manifest.inference.iter().find(|s| s.name == "transcribe")?;
    let base_url = slot
        .requires
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(String::from);
    match slot.provider.as_str() {
        "apple-speech" => Some(Box::new(AppleSpeech::new(
            slot.requires
                .get("command")
                .and_then(|v| v.as_str())
                .map(String::from),
            slot.requires
                .get("locale")
                .and_then(|v| v.as_str())
                .map(String::from),
        ))),
        "whisper-cpp" => Some(Box::new(WhisperCpp::new(
            slot.model.clone().unwrap_or_else(|| "base.en".into()),
            slot.requires
                .get("command")
                .and_then(|v| v.as_str())
                .map(String::from),
        ))),
        "openai" => {
            let key = credential.or_else(|| {
                std::env::var("OPENAI_API_KEY")
                    .ok()
                    .filter(|k| !k.is_empty())
                    .map(Zeroizing::new)
            })?;
            Some(Box::new(OpenAiTranscriber {
                key,
                base_url: base_url.unwrap_or_else(|| "https://api.openai.com/v1".into()),
                model: slot.model.clone().unwrap_or_else(|| "whisper-1".into()),
            }))
        }
        "mock" => Some(Box::new(MockTranscriber)),
        _ => None,
    }
}

/// The transcribe slot's credential blob, if any (the runner decrypts it).
pub fn transcribe_slot(
    manifest: &apiary_core::manifest::Manifest,
) -> Option<&apiary_core::manifest::InferenceSlot> {
    manifest.inference.iter().find(|s| s.name == "transcribe")
}

/// Token estimate for budgeting an audio attachment before any call.
pub fn estimate_audio_tokens(duration_secs: Option<f32>) -> u64 {
    let secs = duration_secs
        .map(|d| d.ceil() as u64)
        .unwrap_or(AUDIO_DEFAULT_SECS);
    secs.max(1) * AUDIO_TOKENS_PER_SEC
}

// ---------------------------------------------------------------- whisper-cpp

pub struct WhisperCpp {
    model: String,
    command: Option<String>,
}

impl WhisperCpp {
    pub fn new(model: String, command: Option<String>) -> Self {
        Self { model, command }
    }

    fn binary(&self) -> String {
        if let Some(c) = &self.command {
            return c.clone();
        }
        // whisper.cpp renamed its CLI (main → whisper-cli); Homebrew ships
        // both names across versions. First one on PATH wins.
        for name in ["whisper-cli", "whisper-cpp", "whisper"] {
            if which(name) {
                return name.into();
            }
        }
        "whisper-cli".into()
    }

    /// Resolve `model` to a ggml file: an explicit path, or a short name
    /// looked up in the usual places (`~/.cache/whisper`, Homebrew share,
    /// `$WHISPER_MODELS`).
    fn model_path(&self) -> Result<PathBuf, crate::Error> {
        let m = PathBuf::from(&self.model);
        if m.is_file() {
            return Ok(m);
        }
        let file = if self.model.starts_with("ggml-") {
            self.model.clone()
        } else {
            format!("ggml-{}.bin", self.model)
        };
        let mut dirs: Vec<PathBuf> = Vec::new();
        if let Ok(d) = std::env::var("WHISPER_MODELS") {
            dirs.push(PathBuf::from(d));
        }
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            dirs.push(home.join(".cache/whisper"));
            dirs.push(home.join(".apiary/models"));
        }
        for prefix in ["/opt/homebrew", "/usr/local", "/usr"] {
            dirs.push(PathBuf::from(prefix).join("share/whisper-cpp/models"));
            dirs.push(PathBuf::from(prefix).join("share/whisper-cpp"));
        }
        for d in &dirs {
            let p = d.join(&file);
            if p.is_file() {
                return Ok(p);
            }
        }
        Err(crate::Error::Provider(format!(
            "whisper-cpp model '{}' not found (looked for {file} in {} places; set \
             WHISPER_MODELS or use a full path; download with e.g. \
             `whisper-cpp-download-ggml-model {}`)",
            self.model,
            dirs.len(),
            self.model
        )))
    }
}

fn which(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Any audio → 16 kHz mono PCM WAV via ffmpeg (whisper.cpp's one input).
fn to_wav16k(input: &std::path::Path, output: &std::path::Path) -> Result<(), crate::Error> {
    let out = Command::new("ffmpeg")
        .args(["-y", "-loglevel", "error", "-i"])
        .arg(input)
        .args(["-ar", "16000", "-ac", "1", "-c:a", "pcm_s16le", "-f", "wav"])
        .arg(output)
        .output()
        .map_err(|e| crate::Error::Provider(format!("ffmpeg (needed to decode audio): {e}")))?;
    if !out.status.success() {
        return Err(crate::Error::Provider(format!(
            "ffmpeg failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Seconds of audio in a 16 kHz mono s16 WAV (data bytes / 32000).
fn wav16k_secs(path: &std::path::Path) -> Option<f32> {
    let len = std::fs::metadata(path).ok()?.len();
    Some(len.saturating_sub(44) as f32 / 32_000.0)
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Result<Self, crate::Error> {
        let d = std::env::temp_dir().join(format!(
            "apiary-audio-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&d)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self(d))
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        // Raw audio is transient host state — never left behind.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ext_for(media_type: &str) -> &'static str {
    match media_type {
        "audio/ogg" | "audio/opus" => "ogg",
        "audio/mpeg" | "audio/mp3" => "mp3",
        "audio/mp4" | "audio/m4a" | "audio/x-m4a" => "m4a",
        "audio/wav" | "audio/x-wav" | "audio/wave" => "wav",
        "audio/webm" => "webm",
        "audio/flac" => "flac",
        _ => "bin",
    }
}

impl Transcriber for WhisperCpp {
    fn id(&self) -> String {
        format!("whisper-cpp/{}", self.model)
    }

    fn transcribe(&self, audio: &[u8], media_type: &str) -> Result<Transcript, crate::Error> {
        let model = self.model_path()?;
        let tmp = TempDir::new()?;
        let input = tmp.0.join(format!("in.{}", ext_for(media_type)));
        let wav = tmp.0.join("in.wav");
        std::fs::write(&input, audio)?;
        to_wav16k(&input, &wav)?;
        let duration = wav16k_secs(&wav);
        if let Some(d) = duration {
            if d > MAX_AUDIO_SECS {
                return Err(crate::Error::Provider(format!(
                    "audio is {d:.0}s — over the {MAX_AUDIO_SECS:.0}s transcription ceiling"
                )));
            }
        }
        let out_base = tmp.0.join("out");
        let out = Command::new(self.binary())
            .arg("-m")
            .arg(&model)
            .arg("-f")
            .arg(&wav)
            .args(["-otxt", "-np", "-nt", "-of"])
            .arg(&out_base)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .output()
            .map_err(|e| crate::Error::Provider(format!("whisper-cpp spawn: {e}")))?;
        if !out.status.success() {
            return Err(crate::Error::Provider(format!(
                "whisper-cpp failed: {}",
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .last()
                    .unwrap_or("")
                    .trim()
            )));
        }
        // -otxt writes <of>.txt; fall back to stdout for older builds.
        let text = std::fs::read_to_string(out_base.with_extension("txt"))
            .unwrap_or_else(|_| String::from_utf8_lossy(&out.stdout).to_string());
        Ok(Transcript {
            text: text.split_whitespace().collect::<Vec<_>>().join(" "),
            engine: self.id(),
            language: None,
            duration_secs: duration,
        })
    }
}

// --------------------------------------------------------------- apple-speech

/// The `services/apple-speech` sidecar: one JSON request line on stdin,
/// one JSON result line on stdout. Pure equipment — it gets audio bytes
/// and nothing else. Resolved from `requires.command`, then
/// `$APIARY_APPLE_SPEECH`, then conventional install locations.
pub struct AppleSpeech {
    command: Option<String>,
    locale: Option<String>,
}

impl AppleSpeech {
    pub fn new(command: Option<String>, locale: Option<String>) -> Self {
        Self { command, locale }
    }

    pub fn binary(&self) -> Result<PathBuf, crate::Error> {
        // An explicit command is a statement, not a hint: if it's wrong,
        // say so rather than quietly using some other binary.
        if let Some(c) = &self.command {
            let p = PathBuf::from(c);
            return if p.is_file() {
                Ok(p)
            } else {
                Err(crate::Error::Provider(format!(
                    "apple-speech: requires.command '{c}' not found"
                )))
            };
        }
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(c) = std::env::var("APIARY_APPLE_SPEECH") {
            candidates.push(PathBuf::from(c));
        }
        if let Some(home) = std::env::var_os("HOME") {
            candidates.push(PathBuf::from(home).join(".apiary/bin/apple-speech"));
        }
        candidates.push(PathBuf::from("/usr/local/bin/apple-speech"));
        candidates.push(PathBuf::from("/opt/homebrew/bin/apple-speech"));
        candidates.into_iter().find(|p| p.is_file()).ok_or_else(|| {
            crate::Error::Provider(
                "apple-speech sidecar not found (build services/apple-speech with \
                     `swift build -c release` and put the binary at ~/.apiary/bin/apple-speech, \
                     or set requires.command / APIARY_APPLE_SPEECH)"
                    .into(),
            )
        })
    }

    pub(crate) fn call(&self, req: &serde_json::Value) -> Result<serde_json::Value, crate::Error> {
        use std::io::Write;
        let bin = self.binary()?;
        let mut child = Command::new(&bin)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("TMPDIR", std::env::var("TMPDIR").unwrap_or_default())
            .spawn()
            .map_err(|e| crate::Error::Provider(format!("apple-speech spawn: {e}")))?;
        {
            let mut stdin = child.stdin.take().expect("piped");
            stdin
                .write_all(req.to_string().as_bytes())
                .and_then(|_| stdin.write_all(b"\n"))
                .map_err(|e| crate::Error::Provider(format!("apple-speech stdin: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| crate::Error::Provider(format!("apple-speech wait: {e}")))?;
        let line = String::from_utf8_lossy(&out.stdout);
        let line = line.lines().last().unwrap_or("").trim();
        if line.is_empty() {
            return Err(crate::Error::Provider(format!(
                "apple-speech produced no result (exit {}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| crate::Error::Provider(format!("apple-speech parse: {e}: {line}")))?;
        if v["ok"].as_bool() != Some(true) {
            return Err(crate::Error::Provider(format!(
                "apple-speech: {}",
                v["error"].as_str().unwrap_or("unknown error")
            )));
        }
        Ok(v)
    }
}

impl Transcriber for AppleSpeech {
    fn id(&self) -> String {
        "apple-speech/SpeechTranscriber".into()
    }

    fn transcribe(&self, audio: &[u8], media_type: &str) -> Result<Transcript, crate::Error> {
        use base64::Engine;
        let mut req = serde_json::json!({
            "op": "transcribe",
            "audio_b64": base64::engine::general_purpose::STANDARD.encode(audio),
            "media_type": media_type,
        });
        if let Some(l) = &self.locale {
            req["locale"] = serde_json::json!(l);
        }
        let v = self.call(&req)?;
        let duration = v["duration_secs"].as_f64().map(|d| d as f32);
        if let Some(d) = duration {
            if d > MAX_AUDIO_SECS {
                return Err(crate::Error::Provider(format!(
                    "audio is {d:.0}s — over the {MAX_AUDIO_SECS:.0}s transcription ceiling"
                )));
            }
        }
        Ok(Transcript {
            text: v["text"].as_str().unwrap_or_default().trim().to_string(),
            engine: v["engine"].as_str().unwrap_or("apple-speech").to_string(),
            language: v["language"].as_str().map(String::from),
            duration_secs: duration,
        })
    }
}

// --------------------------------------------------------------------- openai

pub struct OpenAiTranscriber {
    key: Zeroizing<String>,
    base_url: String,
    model: String,
}

#[derive(Deserialize)]
struct OpenAiTranscription {
    text: String,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    duration: Option<f32>,
}

impl Transcriber for OpenAiTranscriber {
    fn id(&self) -> String {
        format!("openai/{}", self.model)
    }

    fn transcribe(&self, audio: &[u8], media_type: &str) -> Result<Transcript, crate::Error> {
        let part = reqwest::blocking::multipart::Part::bytes(audio.to_vec())
            .file_name(format!("audio.{}", ext_for(media_type)))
            .mime_str(media_type)
            .map_err(|e| crate::Error::Provider(format!("audio mime: {e}")))?;
        let form = reqwest::blocking::multipart::Form::new()
            .text("model", self.model.clone())
            .text("response_format", "verbose_json")
            .part("file", part);
        let resp: OpenAiTranscription = reqwest::blocking::Client::new()
            .post(format!(
                "{}/audio/transcriptions",
                self.base_url.trim_end_matches('/')
            ))
            .bearer_auth(self.key.as_str())
            .multipart(form)
            .send()
            .map_err(|e| crate::Error::Provider(format!("openai transcription: {e}")))?
            .error_for_status()
            .map_err(|e| crate::Error::Provider(format!("openai transcription: {e}")))?
            .json()
            .map_err(|e| crate::Error::Provider(format!("openai transcription parse: {e}")))?;
        Ok(Transcript {
            text: resp.text.trim().to_string(),
            engine: self.id(),
            language: resp.language,
            duration_secs: resp.duration,
        })
    }
}

// ----------------------------------------------------------------------- mock

pub struct MockTranscriber;

impl Transcriber for MockTranscriber {
    fn id(&self) -> String {
        "mock/transcriber".into()
    }
    fn transcribe(&self, audio: &[u8], media_type: &str) -> Result<Transcript, crate::Error> {
        Ok(Transcript {
            text: format!("[mock transcript of {} bytes of {media_type}]", audio.len()),
            engine: self.id(),
            language: Some("en".into()),
            duration_secs: Some(audio.len() as f32 / 32_000.0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_estimate_rounds_up_and_defaults() {
        assert_eq!(estimate_audio_tokens(Some(2.1)), 3 * AUDIO_TOKENS_PER_SEC);
        assert_eq!(estimate_audio_tokens(Some(0.0)), AUDIO_TOKENS_PER_SEC);
        assert_eq!(
            estimate_audio_tokens(None),
            AUDIO_DEFAULT_SECS * AUDIO_TOKENS_PER_SEC
        );
    }

    #[test]
    fn slot_binds_by_name_and_provider() {
        let m = apiary_core::manifest::Manifest::from_yaml(
            r#"
manifest_version: 1
identity:
  npub: npub1m8mfxnr32mlkylq9s0cj5l6vheatdu39kaze26e65ptzfr8vudgse6kgv3
inference:
  - name: brain
    provider: mock
  - name: transcribe
    provider: mock
routing:
  default: brain
connectors: []
memory:
  log: local
governance:
  suspend_keys:
    - npub1kpmddremcthyftcuua6hjkt9hekc729j78qkhfgfvv35efjz0mnsgddfeg
"#,
        )
        .unwrap();
        let t = bind_transcriber(&m, None).expect("mock transcriber binds");
        let out = t.transcribe(b"abc", "audio/ogg").unwrap();
        assert!(out.text.contains("3 bytes"));
        assert_eq!(t.id(), "mock/transcriber");
    }

    #[test]
    fn apple_speech_bad_command_is_a_loud_error() {
        // An explicit command that doesn't exist fails at spawn, clearly.
        let a = AppleSpeech::new(Some("/nonexistent/apple-speech".into()), None);
        let err = a.transcribe(b"", "audio/ogg").unwrap_err().to_string();
        assert!(err.contains("not found") || err.contains("spawn"), "{err}");
    }

    #[test]
    fn whisper_missing_model_is_a_loud_error() {
        let w = WhisperCpp::new("definitely-not-a-model".into(), None);
        let err = w.transcribe(b"", "audio/ogg").unwrap_err().to_string();
        assert!(err.contains("not found"), "{err}");
    }
}
