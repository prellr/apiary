//! Real speak leg on a Mac host: apple-speech sidecar (skipped if absent)
//! and macos-say (skipped off macOS) → OGG/Opus via ffmpeg (skipped if
//! absent). Asserts the transcode really produced Opus, since that is what
//! Telegram's sendVoice requires.

use apiary_runtime::speak::{to_ogg_opus, AppleSpeechSpeaker, MacosSay, Speaker};

fn have(bin: &str) -> bool {
    std::process::Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn assert_is_opus(bytes: &[u8]) {
    assert!(bytes.starts_with(b"OggS"), "not an OGG container");
    // OpusHead appears in the first page.
    assert!(
        bytes[..bytes.len().min(200)]
            .windows(8)
            .any(|w| w == b"OpusHead"),
        "OGG container but no OpusHead — wrong codec"
    );
}

#[test]
fn macos_say_speaks_and_transcodes_to_opus() {
    if !cfg!(target_os = "macos") || !have("say") {
        eprintln!("SKIP: not macOS");
        return;
    }
    if !have("ffmpeg") {
        eprintln!("SKIP: no ffmpeg");
        return;
    }
    let s = MacosSay::new(None)
        .speak("Those are morning glories.")
        .unwrap();
    assert!(s.bytes.len() > 1000);
    let ogg = to_ogg_opus(&s).unwrap();
    assert_is_opus(&ogg.bytes);
    eprintln!(
        "macos-say: {} bytes aiff → {} bytes opus",
        s.bytes.len(),
        ogg.bytes.len()
    );
}

#[test]
fn apple_speech_speaks_and_transcodes_to_opus() {
    let sp = AppleSpeechSpeaker::default_for_host();
    if sp.is_none() || !have("ffmpeg") {
        eprintln!("SKIP: apple-speech sidecar or ffmpeg missing");
        return;
    }
    let started = std::time::Instant::now();
    let s = sp
        .unwrap()
        .speak("Those are morning glories, Ryan.")
        .unwrap();
    assert_eq!(s.media_type, "audio/x-caf");
    let ogg = to_ogg_opus(&s).unwrap();
    assert_is_opus(&ogg.bytes);
    eprintln!(
        "apple-speech: {:.1}s of speech in {:?}, {} bytes opus",
        s.duration_secs.unwrap_or(0.0),
        started.elapsed(),
        ogg.bytes.len()
    );
}
