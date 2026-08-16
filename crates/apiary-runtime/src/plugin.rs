//! Channel Plugin Protocol (`apiary-channel/1`) — the host side.
//!
//! A presence plugin is an executable speaking newline-delimited JSON-RPC
//! 2.0 on stdio (the MCP stdio framing, reused): `initialize` → `poll` →
//! `reply` → `shutdown`. See docs/CHANNEL_PLUGINS.md for the spec and a
//! copyable example. The host spawns plugins with a scrubbed environment
//! and hands the sealed credential's plaintext ONLY at initialize — a
//! plugin never sees the keystore, the manifest, or any other agent's
//! material. Governance (budgets, framing, logging, lease) stays host-side
//! entirely: a misbehaving plugin can at worst misbehave on its own
//! platform.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

pub const PROTOCOL: &str = "apiary-channel/1";
const POLL_MS: u64 = 15_000;
const CALL_TIMEOUT: Duration = Duration::from_secs(40);

/// One installed plugin, from `<home>/plugins.yaml`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginSpec {
    pub name: String,
    pub protocol: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PluginRegistry {
    #[serde(default)]
    pub plugins: Vec<PluginSpec>,
}

/// Load the host's installed plugins (missing file = none).
pub fn load_registry(home: &std::path::Path) -> Result<PluginRegistry, crate::Error> {
    let path = home.join("plugins.yaml");
    if !path.exists() {
        return Ok(PluginRegistry::default());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| crate::Error::Provider(format!("plugins.yaml: {e}")))?;
    serde_yaml_ish(&raw)
}

fn serde_yaml_ish(raw: &str) -> Result<PluginRegistry, crate::Error> {
    // apiary-runtime has no serde_yaml dependency; plugins.yaml is written
    // by hostd (which does) — but the CLI-less path still needs to read
    // it, so accept JSON too and fall back to a minimal YAML subset parse
    // via serde_json when possible.
    if let Ok(reg) = serde_json::from_str::<PluginRegistry>(raw) {
        return Ok(reg);
    }
    // Minimal YAML: rely on the structured writer in hostd producing
    // predictable output. Parse line-wise.
    let mut plugins = Vec::new();
    let mut cur: Option<PluginSpec> = None;
    for line in raw.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("- name:") {
            if let Some(p) = cur.take() {
                plugins.push(p);
            }
            cur = Some(PluginSpec {
                name: rest.trim().to_string(),
                protocol: String::new(),
                command: String::new(),
                args: Vec::new(),
            });
        } else if let Some(p) = cur.as_mut() {
            if let Some(v) = t.strip_prefix("protocol:") {
                p.protocol = v.trim().to_string();
            } else if let Some(v) = t.strip_prefix("command:") {
                p.command = v.trim().to_string();
            } else if let Some(v) = t.strip_prefix("- ") {
                if !t.starts_with("- name:") {
                    p.args.push(v.trim().to_string());
                }
            }
        }
    }
    if let Some(p) = cur.take() {
        plugins.push(p);
    }
    Ok(PluginRegistry { plugins })
}

/// A running plugin subprocess as a ChannelAdapter.
pub struct PluginAdapter {
    name: String,
    child: Child,
    stdin: std::process::ChildStdin,
    lines: mpsc::Receiver<String>,
    next_id: u64,
    describe: String,
}

impl Drop for PluginAdapter {
    fn drop(&mut self) {
        let _ = self.notify("shutdown", json!({}));
        std::thread::sleep(Duration::from_millis(150));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl PluginAdapter {
    /// Spawn and initialize. `credential` is the sealed blob's plaintext,
    /// opened just-in-time by the caller; `config` is the manifest
    /// presence entry's config map.
    pub fn connect(
        spec: &PluginSpec,
        config: &Value,
        credential: Option<&str>,
    ) -> Result<Self, crate::Error> {
        if spec.protocol != PROTOCOL {
            return Err(crate::Error::Provider(format!(
                "plugin '{}' speaks {}, this host speaks {PROTOCOL}",
                spec.name, spec.protocol
            )));
        }
        let mut cmd = Command::new(&spec.command);
        cmd.args(&spec.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear();
        for name in ["PATH", "HOME", "TMPDIR", "LANG"] {
            if let Ok(v) = std::env::var(name) {
                cmd.env(name, v);
            }
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| crate::Error::Provider(format!("plugin '{}' spawn: {e}", spec.name)))?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) if !l.trim().is_empty() => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
        });
        let mut me = Self {
            name: spec.name.clone(),
            child,
            stdin,
            lines: rx,
            next_id: 0,
            describe: String::new(),
        };
        let init = me.request(
            "initialize",
            json!({
                "protocol": PROTOCOL,
                "config": config,
                "credential": credential,
            }),
        )?;
        let result = init.get("result").ok_or_else(|| {
            crate::Error::Provider(format!(
                "plugin '{}' initialize failed: {}",
                me.name,
                init.get("error").cloned().unwrap_or_default()
            ))
        })?;
        me.describe = format!(
            "{}: plugin ready ({})",
            me.name,
            result
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unnamed")
        );
        Ok(me)
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, crate::Error> {
        self.next_id += 1;
        let id = self.next_id;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{msg}")
            .and_then(|_| self.stdin.flush())
            .map_err(|e| crate::Error::Provider(format!("plugin '{}' write: {e}", self.name)))?;
        let deadline = std::time::Instant::now() + CALL_TIMEOUT;
        loop {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| {
                    crate::Error::Provider(format!("plugin '{}': {method} timed out", self.name))
                })?;
            let raw = self.lines.recv_timeout(remaining).map_err(|_| {
                crate::Error::Provider(format!(
                    "plugin '{}': no response to {method} (timeout/EOF)",
                    self.name
                ))
            })?;
            let v: Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("id").and_then(Value::as_u64) == Some(id) {
                return Ok(v);
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), crate::Error> {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        writeln!(self.stdin, "{msg}")
            .and_then(|_| self.stdin.flush())
            .map_err(|e| crate::Error::Provider(format!("plugin '{}' write: {e}", self.name)))?;
        Ok(())
    }
}

impl crate::presence::ChannelAdapter for PluginAdapter {
    fn kind(&self) -> &'static str {
        // Plugin kinds are dynamic; the engine uses this for log actions
        // and framing. Leak once per adapter instance is unacceptable —
        // instead the engine's `{kind}` strings come from here, so return
        // a stable static and carry the real name in describe(). The log
        // action becomes "plugin.mention" with the plugin name in detail.
        "plugin"
    }

    fn describe(&self) -> String {
        self.describe.clone()
    }

    fn next_mention(
        &mut self,
        stop: &AtomicBool,
    ) -> Result<Option<crate::presence::Mention>, crate::Error> {
        if stop.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let resp = self.request("poll", json!({"timeout_ms": POLL_MS}))?;
        let mentions = resp["result"]["mentions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let Some(m) = mentions.first() else {
            return Ok(None); // tick
        };
        Ok(Some(crate::presence::Mention {
            channel: m["channel"].as_str().unwrap_or_default().to_string(),
            author: m["author"].as_str().unwrap_or_default().to_string(),
            text: m["text"].as_str().unwrap_or_default().to_string(),
            reply_ref: m["ref"].as_str().unwrap_or_default().to_string(),
            attachments: parse_attachments(m),
        }))
    }

    fn reply(
        &mut self,
        mention: &crate::presence::Mention,
        text: &str,
    ) -> Result<String, crate::Error> {
        let resp = self.request("reply", json!({"ref": mention.reply_ref, "text": text}))?;
        if let Some(err) = resp.get("error") {
            return Err(crate::Error::Provider(format!(
                "plugin '{}' reply refused: {err}",
                self.name
            )));
        }
        Ok(resp["result"]["id"]
            .as_str()
            .unwrap_or_default()
            .to_string())
    }
}

/// Optional `attachments: [{kind, media_type, base64, duration_secs?}]` on
/// a plugin mention. `images: [{media_type, base64}]` is accepted as an
/// alias (the pre-attachments spelling) for one release. Unknown kinds are
/// dropped, never fatal; the host cap applies.
fn parse_attachments(m: &Value) -> Vec<crate::presence::Attachment> {
    use crate::presence::Attachment;
    let mut out = Vec::new();
    for a in m["attachments"].as_array().into_iter().flatten() {
        let (Some(media_type), Some(base64)) = (a["media_type"].as_str(), a["base64"].as_str())
        else {
            continue;
        };
        let att = match a["kind"].as_str().unwrap_or("image") {
            "image" => Attachment::Image {
                media_type: media_type.into(),
                base64: base64.into(),
            },
            "audio" => Attachment::Audio {
                media_type: media_type.into(),
                base64: base64.into(),
                duration_secs: a["duration_secs"].as_f64().map(|d| d as f32),
            },
            _ => continue,
        };
        out.push(att);
    }
    for i in m["images"].as_array().into_iter().flatten() {
        if let (Some(media_type), Some(base64)) = (i["media_type"].as_str(), i["base64"].as_str()) {
            out.push(Attachment::Image {
                media_type: media_type.into(),
                base64: base64.into(),
            });
        }
    }
    out.truncate(crate::presence::MAX_ATTACHMENTS);
    out
}

#[cfg(test)]
mod attachment_tests {
    use super::*;
    use crate::presence::Attachment;

    #[test]
    fn parses_attachments_and_legacy_images_alias() {
        let m = json!({
            "attachments": [
                {"kind": "image", "media_type": "image/png", "base64": "AA"},
                {"kind": "audio", "media_type": "audio/ogg", "base64": "BB", "duration_secs": 4.5},
                {"kind": "hologram", "media_type": "x/y", "base64": "CC"},
                {"kind": "image", "media_type": "image/png"}
            ],
            "images": [{"media_type": "image/jpeg", "base64": "DD"}]
        });
        let got = parse_attachments(&m);
        assert_eq!(got.len(), 3, "unknown kind + malformed dropped; alias kept");
        assert!(
            matches!(&got[0], Attachment::Image { media_type, .. } if media_type == "image/png")
        );
        assert!(
            matches!(&got[1], Attachment::Audio { duration_secs: Some(d), .. } if (*d - 4.5).abs() < 1e-6)
        );
        assert!(matches!(&got[2], Attachment::Image { base64, .. } if base64 == "DD"));
        assert!(parse_attachments(&json!({"text": "hi"})).is_empty());
    }

    #[test]
    fn framing_names_what_it_cannot_hear() {
        let note = crate::presence::attachment_framing(&[Attachment::Audio {
            media_type: "audio/ogg".into(),
            base64: "x".into(),
            duration_secs: None,
        }]);
        assert!(note.contains("cannot hear"));
        assert!(crate::presence::attachment_framing(&[]).is_empty());
    }
}
