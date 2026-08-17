//! Mock MCP stdio server for tests. MODE=modern speaks 2026-07-28
//! (server/discover, per-request _meta); MODE=legacy demands the
//! initialize handshake first and errors on server/discover, mimicking
//! today's npm-ecosystem servers.

use std::io::{BufRead, Write};

fn main() {
    let legacy = std::env::args().nth(1).as_deref() == Some("legacy")
        || std::env::var("MODE").as_deref() == Ok("legacy");
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut initialized = false;
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let id = v.get("id").cloned();
        let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let reply = match method {
            "server/discover" if !legacy => Some(serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "result": {"supportedVersions": ["2026-07-28"], "serverInfo": {"name": "mock", "version": "0"}},
            })),
            "server/discover" => Some(serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "Method not found"},
            })),
            "initialize" if legacy => {
                initialized = true;
                Some(serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                               "serverInfo": {"name": "mock-legacy", "version": "0"}},
                }))
            }
            "notifications/initialized" => None,
            "tools/list" => {
                if legacy && !initialized {
                    Some(serde_json::json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": {"code": -32002, "message": "not initialized"},
                    }))
                } else {
                    Some(serde_json::json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {"tools": [
                            {"name": "echo", "description": "Echo the input",
                             "annotations": {"readOnlyHint": true},
                             "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
                            {"name": "forbidden.tool", "description": "Should be filtered",
                             "inputSchema": {"type": "object"}},
                        ]},
                    }))
                }
            }
            "tools/call" => {
                let name = v["params"]["name"].as_str().unwrap_or("");
                let args = v["params"]["arguments"].clone();
                Some(serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {"resultType": "complete",
                               "content": [{"type": "text", "text": format!("{name}: {args}")}],
                               "isError": false},
                }))
            }
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
