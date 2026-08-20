//! Era detection + round trips against the mock stdio server, in both
//! protocol eras.

use apiary_runtime::mcp::{Binding, Era, McpClient};
use serde_json::json;

fn mock(mode: &str) -> McpClient {
    McpClient::connect(Binding::Stdio {
        command: env!("CARGO_BIN_EXE_mock-mcp").into(),
        args: vec![mode.into()],
        env_passthrough: vec![],
    })
    .expect("connect mock")
}

#[test]
fn modern_era_detected_and_calls_work() {
    let mut c = mock("modern");
    assert_eq!(c.era, Era::Modern);
    let tools = c.tools_list().unwrap();
    assert!(tools.iter().any(|t| t.name == "echo"));
    let echo = tools.iter().find(|t| t.name == "echo").unwrap().clone();
    assert!(echo.read_only);
    assert!(
        !tools
            .iter()
            .find(|t| t.name == "forbidden.tool")
            .unwrap()
            .read_only
    );
    let out = c.tools_call(&echo, &json!({"text": "hi"})).unwrap();
    assert!(out.text.contains("hi"), "{}", out.text);
    assert!(!out.is_error);
}

#[test]
fn legacy_era_falls_back_to_initialize() {
    let mut c = mock("legacy");
    assert_eq!(c.era, Era::Legacy);
    let tools = c.tools_list().unwrap();
    assert!(tools.iter().any(|t| t.name == "echo"));
    let echo = tools.iter().find(|t| t.name == "echo").unwrap().clone();
    let out = c.tools_call(&echo, &json!({"text": "legacy hi"})).unwrap();
    assert!(out.text.contains("legacy hi"));
}
