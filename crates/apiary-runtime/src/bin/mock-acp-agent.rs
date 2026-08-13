//! Mock ACP agent — a fake foreign harness for tests and demos.
//!
//! Speaks just enough newline-delimited JSON-RPC to exercise the client:
//! initialize → session/new → session/prompt, one message chunk, one tool
//! call that asks permission (so host policy is exercised), then end_turn.

use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn send(v: Value) {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{v}").ok();
    out.flush().ok();
}

fn main() {
    let stdin = std::io::stdin();
    let mut pending_permission: Option<Value> = None;
    for line in stdin.lock().lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };

        // Response to our permission request?
        if pending_permission.is_some() && msg.get("result").is_some() && msg.get("method").is_none()
        {
            let granted = msg["result"]["outcome"]["optionId"] == "allow";
            send(json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "mock-session", "update": {
                "sessionUpdate": "tool_call_update", "toolCallId": "tc1", "title": "write_file",
                "status": if granted { "completed" } else { "failed" }
            }}}));
            let prompt_id = pending_permission.take().unwrap();
            send(json!({"jsonrpc": "2.0", "id": prompt_id, "result": {"stopReason": "end_turn"}}));
            continue;
        }

        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        match msg.get("method").and_then(|m| m.as_str()) {
            Some("initialize") => {
                send(json!({"jsonrpc": "2.0", "id": id, "result": {"protocolVersion": 1, "agentCapabilities": {}}}));
            }
            Some("session/new") => {
                send(json!({"jsonrpc": "2.0", "id": id, "result": {"sessionId": "mock-session"}}));
            }
            Some("session/prompt") => {
                let text = msg["params"]["prompt"][0]["text"].as_str().unwrap_or("");
                send(json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "mock-session", "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": format!("mock harness reply: {text}")}
                }}}));
                send(json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "mock-session", "update": {
                    "sessionUpdate": "tool_call", "toolCallId": "tc1", "title": "write_file", "status": "pending"
                }}}));
                // Ask the client's permission — this is where host floors bite.
                send(json!({"jsonrpc": "2.0", "id": 1000, "method": "session/request_permission", "params": {
                    "sessionId": "mock-session",
                    "toolCall": {"toolCallId": "tc1", "title": "write_file"},
                    "options": [
                        {"optionId": "allow", "name": "Allow once", "kind": "allow_once"},
                        {"optionId": "reject", "name": "Reject once", "kind": "reject_once"}
                    ]
                }}));
                pending_permission = Some(id);
            }
            _ => {
                if !id.is_null() {
                    send(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unsupported"}}));
                }
            }
        }
    }
}
