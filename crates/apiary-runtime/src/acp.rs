//! ACP client — drive a foreign harness (Goose, Claude Code, Codex) as this
//! agent's loop, under Apiary's governance shell (SPEC §2 sidecars).
//!
//! The runtime brings the loop; Apiary supplies everything that isn't the
//! loop: identity (results signed into the log), floors (permission requests
//! route back HERE and are decided by host policy, never by the model), and
//! the record (every tool call and permission decision logged).
//!
//! Wire: newline-delimited JSON-RPC 2.0 over the child's stdio, per the
//! Agent Client Protocol. This is a deliberately minimal sync client for the
//! one-shot runner; when the host daemon goes async, graduate to the
//! official `agent-client-protocol` crate.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Host policy for the harness's permission requests. Default deny: a
/// hijacked or overeager loop is bounded by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMode {
    /// Reject every request (read-only observation of the harness).
    Deny,
    /// Approve every request (the human explicitly opted in for this run).
    Allow,
}

pub struct AcpOutcome {
    /// Accumulated agent text (message chunks joined).
    pub text: String,
    pub stop_reason: String,
    /// (tool title, status) pairs observed via session/update.
    pub tool_calls: Vec<(String, String)>,
    /// (tool title, decision) pairs for permission requests we answered.
    pub permissions: Vec<(String, String)>,
}

/// Run one prompt through an ACP agent subprocess.
pub fn run_acp_prompt(
    command: &str,
    args: &[String],
    workdir: &std::path::Path,
    task: &str,
    mode: PermissionMode,
    turn_timeout: Duration,
) -> Result<AcpOutcome, crate::Error> {
    // The harness gets a MINIMAL environment, not ours: no APIARY_PASSPHRASE,
    // no provider credentials, no session markers. Capability flows through
    // permission-gated tools, never through inherited env. (Filesystem and
    // network isolation still require an OS sandbox — documented limit.)
    const ENV_ALLOWLIST: &[&str] = &["PATH", "HOME", "USER", "SHELL", "LANG", "TMPDIR", "TERM"];
    let mut cmd = Command::new(command);
    cmd.args(args).current_dir(workdir).env_clear();
    for key in ENV_ALLOWLIST {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| crate::Error::Provider(format!("spawn {command}: {e}")))?;
    let result = drive(&mut child, workdir, task, mode, turn_timeout);
    let _ = child.kill();
    let _ = child.wait();
    result
}

fn drive(
    child: &mut Child,
    workdir: &std::path::Path,
    task: &str,
    mode: PermissionMode,
    turn_timeout: Duration,
) -> Result<AcpOutcome, crate::Error> {
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");

    // Reader thread → channel, so every wait has a real timeout.
    let (tx, rx) = mpsc::channel::<Value>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if tx.send(v).is_err() {
                    break;
                }
            }
        }
    });

    let mut next_id = 0i64;
    let mut send_request = |stdin: &mut std::process::ChildStdin,
                            method: &str,
                            params: Value|
     -> Result<i64, crate::Error> {
        next_id += 1;
        let frame = json!({"jsonrpc": "2.0", "id": next_id, "method": method, "params": params});
        writeln!(stdin, "{frame}")
            .map_err(|e| crate::Error::Provider(format!("acp write: {e}")))?;
        Ok(next_id)
    };

    let mut out = AcpOutcome {
        text: String::new(),
        stop_reason: "unknown".into(),
        tool_calls: Vec::new(),
        permissions: Vec::new(),
    };

    // 1. initialize — we advertise no fs/terminal capabilities: the harness
    //    gets capability through permission-gated tools, not through us.
    let init_id = send_request(
        &mut stdin,
        "initialize",
        json!({"protocolVersion": 1, "clientCapabilities": {"fs": {"readTextFile": false, "writeTextFile": false}}}),
    )?;
    let mut session_id: Option<String> = None;
    let mut new_id: Option<i64> = None;
    let mut prompt_id: Option<i64> = None;

    loop {
        let msg = rx
            .recv_timeout(turn_timeout)
            .map_err(|_| crate::Error::Provider("acp: agent timed out or exited".into()))?;

        // Agent → client REQUEST (has id + method): permission requests get
        // host policy; anything else is politely unsupported.
        if let (Some(id), Some(method)) =
            (msg.get("id"), msg.get("method").and_then(|m| m.as_str()))
        {
            match method {
                "session/request_permission" => {
                    let title = msg["params"]["toolCall"]["title"]
                        .as_str()
                        .unwrap_or("unnamed tool")
                        .to_string();
                    let options = msg["params"]["options"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    // Strict selection: an option is only acceptable if its
                    // kind matches the mode's intent. Deny mode NEVER falls
                    // back to an allow option — a malformed option list gets
                    // a JSON-RPC error, which the harness must treat as
                    // not-granted.
                    let acceptable = |kind: &str| match mode {
                        PermissionMode::Allow => kind.starts_with("allow"),
                        PermissionMode::Deny => {
                            kind.starts_with("reject") || kind.starts_with("deny")
                        }
                    };
                    let choice = options.iter().find_map(|o| {
                        let kind = o["kind"].as_str()?;
                        if !acceptable(kind) {
                            return None;
                        }
                        Some((o["optionId"].as_str()?.to_string(), kind.to_string()))
                    });
                    let resp = match choice {
                        Some((option_id, kind)) => {
                            out.permissions.push((title, kind));
                            json!({"jsonrpc": "2.0", "id": id, "result": {"outcome": {"outcome": "selected", "optionId": option_id}}})
                        }
                        None => {
                            out.permissions
                                .push((title, "refused (no acceptable option)".into()));
                            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "no permission option acceptable to host policy"}})
                        }
                    };
                    writeln!(stdin, "{resp}")
                        .map_err(|e| crate::Error::Provider(format!("acp write: {e}")))?;
                }
                other => {
                    let resp = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("client does not support {other}")}});
                    writeln!(stdin, "{resp}")
                        .map_err(|e| crate::Error::Provider(format!("acp write: {e}")))?;
                }
            }
            continue;
        }

        // NOTIFICATION: session/update carries the stream.
        if msg.get("method").and_then(|m| m.as_str()) == Some("session/update") {
            let update = &msg["params"]["update"];
            match update["sessionUpdate"].as_str().unwrap_or("") {
                "agent_message_chunk" => {
                    if let Some(t) = update["content"]["text"].as_str() {
                        out.text.push_str(t);
                    }
                }
                "tool_call" | "tool_call_update" => {
                    let title = update["title"].as_str().unwrap_or("").to_string();
                    let status = update["status"].as_str().unwrap_or("pending").to_string();
                    if !title.is_empty() {
                        out.tool_calls.push((title, status));
                    }
                }
                _ => {}
            }
            continue;
        }

        // RESPONSE to one of our requests.
        if let Some(id) = msg.get("id").and_then(|i| i.as_i64()) {
            if let Some(err) = msg.get("error") {
                return Err(crate::Error::Provider(format!(
                    "acp error on request {id}: {}",
                    err["message"].as_str().unwrap_or("unknown")
                )));
            }
            if id == init_id {
                // The session's working directory is the AGENT's dir — the
                // harness works in the agent's world, not the invoking
                // shell's. (v1 shipped env::current_dir() here; a live run
                // promptly listed the user's home directory. Evidence-cited
                // fix.) Absolute path per the ACP spec.
                let cwd = workdir
                    .canonicalize()
                    .unwrap_or_else(|_| workdir.to_path_buf());
                new_id = Some(send_request(
                    &mut stdin,
                    "session/new",
                    json!({"cwd": cwd, "mcpServers": []}),
                )?);
            } else if Some(id) == new_id {
                let sid = msg["result"]["sessionId"]
                    .as_str()
                    .ok_or_else(|| crate::Error::Provider("acp: no sessionId".into()))?
                    .to_string();
                prompt_id = Some(send_request(
                    &mut stdin,
                    "session/prompt",
                    json!({"sessionId": sid, "prompt": [{"type": "text", "text": task}]}),
                )?);
                session_id = Some(sid);
            } else if Some(id) == prompt_id {
                out.stop_reason = msg["result"]["stopReason"]
                    .as_str()
                    .unwrap_or("end_turn")
                    .to_string();
                let _ = session_id; // session ends with the one-shot run
                return Ok(out);
            }
        }
    }
}
