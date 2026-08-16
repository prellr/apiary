//! Real whisper.cpp leg: skipped (loudly) unless the engine + a model are
//! present on this host — CI stays green, a Mac with equipment proves it.

use apiary_runtime::transcribe::{Transcriber, WhisperCpp};

#[test]
fn whisper_cpp_transcribes_a_real_ogg_voice_note() {
    let have_cli = std::process::Command::new("which")
        .arg("whisper-cli")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let w = WhisperCpp::new("base.en".into(), None);
    let ogg = include_bytes!("fixtures/voice-probe.ogg");
    match (have_cli, w.transcribe(ogg, "audio/ogg")) {
        (false, _) => eprintln!("SKIP: whisper-cli not installed"),
        (true, Err(e)) if e.to_string().contains("not found") => {
            eprintln!("SKIP: no ggml-base.en.bin on this host ({e})")
        }
        (true, Err(e)) => panic!("whisper failed with equipment present: {e}"),
        (true, Ok(t)) => {
            let text = t.text.to_lowercase();
            assert!(text.contains("flowers"), "unexpected transcript: {text}");
            assert!(text.contains("gravel"), "unexpected transcript: {text}");
            assert_eq!(t.engine, "whisper-cpp/base.en");
            assert!(t.duration_secs.unwrap_or(0.0) > 2.0);
        }
    }
}
