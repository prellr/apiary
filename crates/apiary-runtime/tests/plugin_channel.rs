//! The reference plugin over a REAL subprocess: initialize → poll →
//! mention → reply, asserted through the plugin's reply file.

use apiary_runtime::plugin::{PluginAdapter, PluginSpec, PROTOCOL};
use apiary_runtime::presence::ChannelAdapter;
use serde_json::json;
use std::sync::atomic::AtomicBool;

#[test]
fn reference_plugin_round_trip() {
    let reply_file =
        std::env::temp_dir().join(format!("apiary-mock-channel-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&reply_file);
    let spec = PluginSpec {
        name: "mock".into(),
        protocol: PROTOCOL.into(),
        command: env!("CARGO_BIN_EXE_mock-channel").into(),
        args: vec![],
    };
    let mut adapter = PluginAdapter::connect(
        &spec,
        &json!({"reply_file": reply_file.to_string_lossy()}),
        Some("fake-platform-token"),
    )
    .expect("plugin connects and initializes");
    let stop = AtomicBool::new(false);
    // First poll ticks, second yields the scripted mention.
    let mut mention = None;
    for _ in 0..5 {
        if let Some(m) = adapter.next_mention(&stop).unwrap() {
            mention = Some(m);
            break;
        }
    }
    let mention = mention.expect("mock emits a mention");
    assert_eq!(mention.channel, "mock-room");
    assert!(mention.text.contains("ping"));
    let id = adapter
        .reply(
            &mention,
            &apiary_runtime::presence::Reply::text("pong through the governed path"),
        )
        .unwrap();
    assert_eq!(id, "mock-reply-1");
    drop(adapter); // graceful shutdown path
    let written = std::fs::read_to_string(&reply_file).unwrap();
    assert!(written.contains("pong through the governed path"));
    let _ = std::fs::remove_file(&reply_file);
}
