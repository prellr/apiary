//! Real apple-speech leg: skipped (loudly) unless the sidecar is installed
//! on this host — CI stays green, a macOS 26 host proves it.

use apiary_runtime::transcribe::{AppleSpeech, Transcriber};

#[test]
fn apple_speech_transcribes_a_real_ogg_voice_note() {
    let a = AppleSpeech::new(None, None);
    if a.binary().is_err() {
        eprintln!("SKIP: apple-speech sidecar not installed");
        return;
    }
    let ogg = include_bytes!("fixtures/voice-probe.ogg");
    let started = std::time::Instant::now();
    let t = a
        .transcribe(ogg, "audio/ogg")
        .expect("sidecar present but transcription failed");
    let text = t.text.to_lowercase();
    assert!(text.contains("flowers"), "unexpected transcript: {text}");
    assert!(text.contains("gravel"), "unexpected transcript: {text}");
    assert_eq!(t.engine, "apple-speech/SpeechTranscriber");
    assert!(t.duration_secs.unwrap_or(0.0) > 2.0);
    eprintln!("apple-speech: {:?} in {:?}", t.text, started.elapsed());
}
