//! Connectors — SPEC §6. Everything capable is a connector; the core has
//! custody, connectors have capability. A connector absent from the manifest
//! is a capability that does not exist (default-deny by construction).
//!
//! Caps come from the manifest entry and are enforced HERE, host-side —
//! the model's arguments are requests, not commands.

use apiary_core::custody::{AgentHandle, Custody};
use apiary_core::manifest::Manifest;
use nostr::prelude::*;
use serde_json::{json, Value};

/// A connector's tool-facing definition (Anthropic tool schema shape).
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

pub trait Connector {
    fn def(&self) -> ToolDef;
    /// Execute with host-checked caps. Custody is passed so signing/decrypt
    /// happens here, at call time — the model never holds material.
    fn execute(
        &self,
        custody: &Custody,
        agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error>;
}

/// Build the agent's connector set from its manifest. Unknown kinds are an
/// error, not a skip — a manifest declaring a capability the host can't
/// bind should fail loudly at run start, not silently at dispatch.
pub fn bind_connectors(manifest: &Manifest) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    let mut out: Vec<Box<dyn Connector>> = Vec::new();
    for entry in &manifest.connectors {
        match entry.kind.as_str() {
            "nostr-publish" => {
                let relays: Vec<String> = entry
                    .caps
                    .get("relays")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|r| r.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                if relays.is_empty() {
                    return Err(crate::Error::Provider(
                        "nostr-publish requires caps.relays (an allowlist — \
                         the agent may only publish where the manifest says)"
                            .into(),
                    ));
                }
                out.push(Box::new(NostrPublish { relays }));
            }
            "mock-echo" => out.push(Box::new(MockEcho)),
            other => {
                return Err(crate::Error::Provider(format!(
                    "unknown connector kind '{other}' (host binds: nostr-publish, mock-echo)"
                )))
            }
        }
    }
    Ok(out)
}

/// Publish a kind-1 note to the manifest-allowlisted relays, signed by the
/// agent's own key — the one connector whose credential IS the identity.
pub struct NostrPublish {
    relays: Vec<String>,
}

impl Connector for NostrPublish {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: "nostr_publish".into(),
            description: format!(
                "Publish a public nostr note (kind 1), signed with your own identity key. \
                 It will be permanently attributable to you on: {}. \
                 Use it when the task asks you to post, announce, or say something publicly.",
                self.relays.join(", ")
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "The note text to publish."
                    }
                },
                "required": ["content"],
                "additionalProperties": false
            }),
        }
    }

    fn execute(
        &self,
        custody: &Custody,
        agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let content = args
            .get("content")
            .and_then(|c| c.as_str())
            .ok_or_else(|| crate::Error::Provider("nostr_publish: missing content".into()))?;
        // Custody signs; the relay client only ever sees the finished event.
        let event = custody.sign(agent, EventBuilder::new(Kind::TextNote, content))?;
        let mut acks = Vec::new();
        let mut failures = Vec::new();
        for relay in &self.relays {
            match publish_to_relay(relay, &event) {
                Ok(msg) => acks.push(format!("{relay}: {msg}")),
                Err(e) => failures.push(format!("{relay}: {e}")),
            }
        }
        if acks.is_empty() {
            return Err(crate::Error::Provider(format!(
                "nostr_publish: no relay accepted the note ({})",
                failures.join("; ")
            )));
        }
        Ok(json!({
            "event_id": event.id.to_hex(),
            "accepted": acks,
            "failed": failures,
        })
        .to_string())
    }
}

/// Minimal sync nostr publish: ["EVENT", …] → wait for ["OK", …].
fn publish_to_relay(url: &str, event: &Event) -> Result<String, crate::Error> {
    use tungstenite::Message;
    let (mut socket, _) = tungstenite::connect(url)
        .map_err(|e| crate::Error::Provider(format!("connect: {e}")))?;
    let frame = json!(["EVENT", serde_json::from_str::<Value>(&event.as_json())?]);
    socket
        .send(Message::Text(frame.to_string().into()))
        .map_err(|e| crate::Error::Provider(format!("send: {e}")))?;
    // Read until an OK for our event id (relays may send other frames first).
    for _ in 0..10 {
        let msg = socket
            .read()
            .map_err(|e| crate::Error::Provider(format!("read: {e}")))?;
        if let Message::Text(text) = msg {
            let v: Value = serde_json::from_str(&text)?;
            if v.get(0).and_then(|t| t.as_str()) == Some("OK")
                && v.get(1).and_then(|id| id.as_str()) == Some(&event.id.to_hex())
            {
                let accepted = v.get(2).and_then(|b| b.as_bool()).unwrap_or(false);
                let detail = v.get(3).and_then(|m| m.as_str()).unwrap_or("");
                let _ = socket.close(None);
                return if accepted {
                    Ok(if detail.is_empty() { "accepted".into() } else { detail.into() })
                } else {
                    Err(crate::Error::Provider(format!("rejected: {detail}")))
                };
            }
        }
    }
    Err(crate::Error::Provider("no OK response".into()))
}

/// Test connector: echoes its arguments. Lets tests exercise the full
/// dispatch + logging path with no network.
pub struct MockEcho;

impl Connector for MockEcho {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: "mock_echo".into(),
            description: "Echo the input back (test connector).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
                "additionalProperties": false
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        Ok(format!("echo: {}", args.get("text").and_then(|t| t.as_str()).unwrap_or("")))
    }
}
