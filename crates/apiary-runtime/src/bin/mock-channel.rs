//! Reference Channel Plugin (`apiary-channel/1`) — and the test double.
//!
//! Reads newline JSON-RPC from stdin, writes to stdout. Behavior: after
//! `initialize`, the SECOND `poll` yields one scripted mention; `reply`
//! appends the text to the file named by config.reply_file (so tests can
//! assert the governed reply arrived) and returns an id. This file is the
//! canonical "how do I write a plugin" answer — ~80 lines, no framework.

use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut reply_file: Option<String> = None;
    let mut polls = 0u32;
    let mut mention_sent = false;
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let id = v.get("id").cloned();
        let reply = match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
            "initialize" => {
                reply_file = v["params"]["config"]["reply_file"]
                    .as_str()
                    .map(String::from);
                Some(serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {"name": "mock-channel", "kind": "mock"},
                }))
            }
            "poll" => {
                polls += 1;
                let mentions = if polls >= 2 && !mention_sent {
                    mention_sent = true;
                    serde_json::json!([{
                        "ref": "m1", "channel": "mock-room",
                        "author": "tester", "text": "@agent ping from the mock platform"
                    }])
                } else {
                    // Real plugins long-poll their platform here; the mock
                    // just ticks fast so tests stay quick.
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    serde_json::json!([])
                };
                Some(serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "result": {"mentions": mentions},
                }))
            }
            "reply" => {
                if let Some(path) = &reply_file {
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                    {
                        let _ = writeln!(f, "{}", v["params"]["text"].as_str().unwrap_or(""));
                    }
                }
                Some(serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "result": {"id": "mock-reply-1"},
                }))
            }
            "shutdown" => break,
            _ => id.map(|id| {
                serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {"code": -32601, "message": "Method not found"},
                })
            }),
        };
        if let Some(r) = reply {
            writeln!(out, "{r}").ok();
            out.flush().ok();
        }
    }
}
