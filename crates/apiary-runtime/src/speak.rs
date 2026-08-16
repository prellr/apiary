//! Speech synthesis — the `speak` inference slot. Text a governed run
//! produced becomes audio a channel can deliver as a voice reply. The text
//! ALWAYS travels with the audio (caption / message body / log): voice is
//! a rendering of the reply, never a replacement for the record.
//!
//! Same treatment as `embed` and `transcribe`: manifest-declared, host-
//! provided engine, gracefully absent (no slot → text replies). Bindings:
//! - `apple-speech`: the sidecar's `speak` op (AVSpeechSynthesizer). Mac
//!   hosts; nothing leaves the machine.
//! - `macos-say`: the `say` CLI — zero setup on any Mac; same voices.
//! - `openai`: `/audio/speech` (tts-1 etc.); `requires.base_url` for any
//!   compatible endpoint. Cloud — opt in per manifest.
//! - `mock`: tests.
//!
//! Engines return whatever container they natively make (CAF, AIFF, MP3);
//! `to_ogg_opus` transcodes with ffmpeg for platforms that want OGG/Opus
//! (Telegram's `sendVoice`). Budget: TTS is charged by output characters
//! (`SPEAK_TOKENS_PER_CHAR`), logged as its own `speak` entry.

use std::path::PathBuf;
use std::process::Command;
use zeroize::Zeroizing;

/// Charge for synthesis: ~1 token per 4 characters, like text.
pub const SPEAK_TOKENS_PER_CHAR: u64 = 1;
pub const SPEAK_CHARS_PER_TOKEN: u64 = 4;
/// Longest reply we'll voice — beyond this, text only (a wall of audio is
/// worse than a wall of text; the text still goes).
pub const MAX_SPEAK_CHARS: usize = 1500;

#[derive(Debug, Clone)]
pub struct Speech {
    pub media_type: String,
    pub bytes: Vec<u8>,
    pub duration_secs: Option<f32>,
    pub engine: String,
}

pub trait Speaker {
    fn speak(&self, text: &str) -> Result<Speech, crate::Error>;
    fn id(&self) -> String;
}

pub fn speak_slot(
    manifest: &apiary_core::manifest::Manifest,
) -> Option<&apiary_core::manifest::InferenceSlot> {
    manifest.inference.iter().find(|s| s.name == "speak")
}

/// Bind a speaker from the manifest's `speak` slot, if declared.
pub fn bind_speaker(
    manifest: &apiary_core::manifest::Manifest,
    credential: Option<Zeroizing<String>>,
) -> Option<Box<dyn Speaker>> {
    let slot = speak_slot(manifest)?;
    let voice = slot
        .requires
        .get("voice")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| slot.model.clone());
    match slot.provider.as_str() {
        "apple-speech" => Some(Box::new(AppleSpeechSpeaker {
            sidecar: crate::transcribe::AppleSpeech::new(
                slot.requires
                    .get("command")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                None,
            ),
            voice,
            rate: slot.requires.get("rate").and_then(|v| v.as_f64()),
        })),
        "macos-say" => Some(Box::new(MacosSay { voice })),
        "openai" => {
            let key = credential.or_else(|| {
                std::env::var("OPENAI_API_KEY")
                    .ok()
                    .filter(|k| !k.is_empty())
                    .map(Zeroizing::new)
            })?;
            Some(Box::new(OpenAiSpeaker {
                key,
                base_url: slot
                    .requires
                    .get("base_url")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| "https://api.openai.com/v1".into()),
                model: slot.model.clone().unwrap_or_else(|| "tts-1".into()),
                voice: slot
                    .requires
                    .get("voice")
                    .and_then(|v| v.as_str())
                    .unwrap_or("alloy")
                    .to_string(),
            }))
        }
        "mock" => Some(Box::new(MockSpeaker)),
        _ => None,
    }
}

pub fn estimate_speak_tokens(text: &str) -> u64 {
    (text.chars().count() as u64 / SPEAK_CHARS_PER_TOKEN + 1) * SPEAK_TOKENS_PER_CHAR
}

/// Transcode any audio to OGG/Opus (Telegram voice notes, and a compact
/// wire format generally). ffmpeg is the accepted equipment dependency for
/// this path only.
pub fn to_ogg_opus(speech: &Speech) -> Result<Speech, crate::Error> {
    if speech.media_type == "audio/ogg" {
        return Ok(speech.clone());
    }
    let dir = temp_dir()?;
    let input = dir.0.join(format!("in.{}", ext_for(&speech.media_type)));
    let out = dir.0.join("out.ogg");
    std::fs::write(&input, &speech.bytes)?;
    let o = Command::new("ffmpeg")
        .args(["-y", "-loglevel", "error", "-i"])
        .arg(&input)
        .args([
            "-c:a",
            "libopus",
            "-b:a",
            "32k",
            "-application",
            "voip",
            "-f",
            "ogg",
        ])
        .arg(&out)
        .output()
        .map_err(|e| crate::Error::Provider(format!("ffmpeg (needed for OGG/Opus): {e}")))?;
    if !o.status.success() {
        return Err(crate::Error::Provider(format!(
            "ffmpeg transcode failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )));
    }
    Ok(Speech {
        media_type: "audio/ogg".into(),
        bytes: std::fs::read(&out)?,
        duration_secs: speech.duration_secs,
        engine: speech.engine.clone(),
    })
}

fn ext_for(media_type: &str) -> &'static str {
    match media_type {
        "audio/x-caf" => "caf",
        "audio/aiff" | "audio/x-aiff" => "aiff",
        "audio/mpeg" | "audio/mp3" => "mp3",
        "audio/wav" | "audio/x-wav" => "wav",
        "audio/ogg" => "ogg",
        "audio/mp4" | "audio/m4a" => "m4a",
        _ => "bin",
    }
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn temp_dir() -> Result<TempDir, crate::Error> {
    let d = std::env::temp_dir().join(format!(
        "apiary-speak-{}-{}",
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
    Ok(TempDir(d))
}

// --------------------------------------------------------------- apple-speech

pub struct AppleSpeechSpeaker {
    sidecar: crate::transcribe::AppleSpeech,
    voice: Option<String>,
    rate: Option<f64>,
}

impl AppleSpeechSpeaker {
    /// The host's default sidecar, or None if it isn't installed.
    pub fn default_for_host() -> Option<Self> {
        let sidecar = crate::transcribe::AppleSpeech::new(None, None);
        sidecar.binary().ok()?;
        Some(Self {
            sidecar,
            voice: None,
            rate: None,
        })
    }
}

impl Speaker for AppleSpeechSpeaker {
    fn id(&self) -> String {
        "apple-speech/AVSpeechSynthesizer".into()
    }
    fn speak(&self, text: &str) -> Result<Speech, crate::Error> {
        use base64::Engine;
        let mut req = serde_json::json!({ "op": "speak", "text": text });
        if let Some(v) = &self.voice {
            req["voice"] = serde_json::json!(v);
        }
        if let Some(r) = self.rate {
            req["rate"] = serde_json::json!(r);
        }
        let v = self.sidecar.call(&req)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(v["audio_b64"].as_str().unwrap_or_default())
            .map_err(|e| crate::Error::Provider(format!("apple-speech audio: {e}")))?;
        Ok(Speech {
            media_type: v["media_type"]
                .as_str()
                .unwrap_or("audio/x-caf")
                .to_string(),
            bytes,
            duration_secs: v["duration_secs"].as_f64().map(|d| d as f32),
            engine: v["engine"].as_str().unwrap_or("apple-speech").to_string(),
        })
    }
}

// ------------------------------------------------------------------ macos-say

pub struct MacosSay {
    voice: Option<String>,
}

impl MacosSay {
    pub fn new(voice: Option<String>) -> Self {
        Self { voice }
    }
}

impl Speaker for MacosSay {
    fn id(&self) -> String {
        format!("macos-say/{}", self.voice.as_deref().unwrap_or("default"))
    }
    fn speak(&self, text: &str) -> Result<Speech, crate::Error> {
        let dir = temp_dir()?;
        let out = dir.0.join("out.aiff");
        let mut cmd = Command::new("say");
        if let Some(v) = &self.voice {
            cmd.arg("-v").arg(v);
        }
        // Text via stdin, never argv (argv is visible to `ps`).
        cmd.arg("-o").arg(&out).arg("-f").arg("-");
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| crate::Error::Provider(format!("say: {e}")))?;
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().expect("piped");
            stdin
                .write_all(text.as_bytes())
                .map_err(|e| crate::Error::Provider(format!("say stdin: {e}")))?;
        }
        let o = child
            .wait_with_output()
            .map_err(|e| crate::Error::Provider(format!("say: {e}")))?;
        if !o.status.success() {
            return Err(crate::Error::Provider(format!(
                "say failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            )));
        }
        let bytes = std::fs::read(&out)?;
        Ok(Speech {
            media_type: "audio/aiff".into(),
            bytes,
            duration_secs: None,
            engine: self.id(),
        })
    }
}

// --------------------------------------------------------------------- openai

pub struct OpenAiSpeaker {
    key: Zeroizing<String>,
    base_url: String,
    model: String,
    voice: String,
}

impl Speaker for OpenAiSpeaker {
    fn id(&self) -> String {
        format!("openai/{}/{}", self.model, self.voice)
    }
    fn speak(&self, text: &str) -> Result<Speech, crate::Error> {
        let resp = reqwest::blocking::Client::new()
            .post(format!(
                "{}/audio/speech",
                self.base_url.trim_end_matches('/')
            ))
            .bearer_auth(self.key.as_str())
            .json(&serde_json::json!({
                "model": self.model, "voice": self.voice, "input": text,
                "response_format": "opus",
            }))
            .send()
            .map_err(|e| crate::Error::Provider(format!("openai speech: {e}")))?
            .error_for_status()
            .map_err(|e| crate::Error::Provider(format!("openai speech: {e}")))?;
        let bytes = resp
            .bytes()
            .map_err(|e| crate::Error::Provider(format!("openai speech body: {e}")))?
            .to_vec();
        Ok(Speech {
            media_type: "audio/ogg".into(),
            bytes,
            duration_secs: None,
            engine: self.id(),
        })
    }
}

// ----------------------------------------------------------------------- mock

pub struct MockSpeaker;
impl Speaker for MockSpeaker {
    fn id(&self) -> String {
        "mock/speaker".into()
    }
    fn speak(&self, text: &str) -> Result<Speech, crate::Error> {
        Ok(Speech {
            media_type: "audio/ogg".into(),
            bytes: format!("OggS[mock speech of {} chars]", text.chars().count()).into_bytes(),
            duration_secs: Some(text.chars().count() as f32 / 15.0),
            engine: self.id(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_and_mock_are_sane() {
        assert_eq!(estimate_speak_tokens(""), 1);
        assert_eq!(estimate_speak_tokens("abcdefgh"), 3);
        let s = MockSpeaker.speak("hello world").unwrap();
        assert_eq!(s.media_type, "audio/ogg");
        assert!(
            to_ogg_opus(&s).unwrap().bytes == s.bytes,
            "ogg passes through untouched"
        );
    }
}
