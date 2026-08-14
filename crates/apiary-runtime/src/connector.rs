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

/// The connector kinds this host can bind — the one list (README:
/// "one list per concept"); bind_connectors and the API both read it.
pub const BOUND_KINDS: &[&str] = &["nostr-publish", "mock-echo", "mcp"];

/// Build the agent's connector set from its manifest. Unknown kinds are an
/// error, not a skip — a manifest declaring a capability the host can't
/// bind should fail loudly at run start, not silently at dispatch.
pub fn bind_connectors(
    manifest: &Manifest,
    custody: &Custody,
    agent: &AgentHandle,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    let mut out: Vec<Box<dyn Connector>> = Vec::new();
    for entry in &manifest.connectors {
        match entry.kind.as_str() {
            "mcp" => out.extend(bind_mcp(entry, custody, agent)?),
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
                    "unknown connector kind '{other}' (host binds: {})",
                    BOUND_KINDS.join(", ")
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
            match crate::relay::publish(relay, &event) {
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
        Ok(format!(
            "echo: {}",
            args.get("text").and_then(|t| t.as_str()).unwrap_or("")
        ))
    }
}

// ---------------------------------------------------------------- mcp

/// Bind an `mcp` manifest entry: connect (era-detected), list the server's
/// tools, clamp to the human-owned `allowed_tools` allowlist, and expose
/// each surviving tool as its own Connector. Caps:
///
/// ```yaml
/// - type: mcp
///   caps:
///     transport: stdio           # or "http"
///     command: npx               # stdio only
///     args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
///     env: []                    # env var NAMES passed through (scrubbed otherwise)
///     url: https://…/mcp         # http only
///     allowed_tools: [read_text_file, list_directory]   # REQUIRED; ["*"] = all
///   credential: <nip44 blob>     # http only: bearer token or OAuth JSON
/// ```
///
/// The allowlist is required and enforced host-side: an MCP server offers
/// whatever it likes; the manifest decides what the agent may touch.
fn bind_mcp(
    entry: &apiary_core::manifest::Connector,
    custody: &Custody,
    agent: &AgentHandle,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    use std::sync::{Arc, Mutex};
    let cap_str = |k: &str| entry.caps.get(k).and_then(|v| v.as_str()).map(String::from);
    let cap_list = |k: &str| -> Vec<String> {
        entry
            .caps
            .get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let allowed = cap_list("allowed_tools");
    if allowed.is_empty() {
        return Err(crate::Error::Provider(
            "mcp connector requires caps.allowed_tools (an explicit allowlist; [\"*\"] \
             grants every tool the server offers — say so deliberately)"
                .into(),
        ));
    }
    let transport = cap_str("transport").unwrap_or_else(|| "stdio".into());
    // Sealed credential: either a raw bearer token or an OAuth JSON object
    // ({"type":"oauth","access_token":…}). Opened just-in-time, per use.
    let credential_plain = match &entry.credential {
        Some(blob) => Some(custody.open(agent, blob)?.as_str().to_string()),
        None => None,
    };
    let (binding, refresh) = match transport.as_str() {
        "stdio" => (
            crate::mcp::Binding::Stdio {
                command: cap_str("command").ok_or_else(|| {
                    crate::Error::Provider("mcp stdio requires caps.command".into())
                })?,
                args: cap_list("args"),
                env_passthrough: cap_list("env"),
            },
            None,
        ),
        "http" => {
            let url = cap_str("url")
                .ok_or_else(|| crate::Error::Provider("mcp http requires caps.url".into()))?;
            let (bearer, refresh) = match credential_plain.as_deref() {
                None => (None, None),
                Some(raw) => match serde_json::from_str::<Value>(raw) {
                    Ok(v) if v.get("type").and_then(Value::as_str) == Some("oauth") => (
                        v.get("access_token")
                            .and_then(Value::as_str)
                            .map(String::from),
                        Some(v),
                    ),
                    _ => (Some(raw.to_string()), None),
                },
            };
            (crate::mcp::Binding::Http { url, bearer }, refresh)
        }
        other => {
            return Err(crate::Error::Provider(format!(
                "mcp transport '{other}' not supported (stdio | http)"
            )))
        }
    };
    let mut client = crate::mcp::McpClient::connect(binding)?;
    let tools = client.tools_list()?;
    let wildcard = allowed.iter().any(|a| a == "*");
    let granted: Vec<crate::mcp::McpTool> = tools
        .into_iter()
        .filter(|t| wildcard || allowed.contains(&t.name))
        .collect();
    if granted.is_empty() {
        return Err(crate::Error::Provider(
            "mcp: server offered no tool matching caps.allowed_tools — \
             check the allowlist against the server's actual tool names"
                .into(),
        ));
    }
    let shared = Arc::new(Mutex::new(client));
    let mut out: Vec<Box<dyn Connector>> = Vec::new();
    let mut used_names: Vec<String> = Vec::new();
    for tool in granted {
        let mut name = crate::mcp::model_tool_name(&tool.name);
        while used_names.contains(&name) {
            name.truncate(60);
            name.push('x');
        }
        used_names.push(name.clone());
        out.push(Box::new(McpToolConnector {
            model_name: name,
            tool,
            client: shared.clone(),
            refresh: refresh.clone(),
        }));
    }
    Ok(out)
}

struct McpToolConnector {
    model_name: String,
    tool: crate::mcp::McpTool,
    client: std::sync::Arc<std::sync::Mutex<crate::mcp::McpClient>>,
    /// OAuth material for 401 recovery: {"token_endpoint","client_id","refresh_token",…}.
    refresh: Option<Value>,
}

impl Connector for McpToolConnector {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: self.model_name.clone(),
            description: format!(
                "{} (via a granted MCP server; the manifest allowlists this tool)",
                self.tool.description
            ),
            input_schema: self.tool.input_schema.clone(),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let mut client = self
            .client
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let outcome =
            match client.tools_call(&self.tool, args) {
                Ok(o) => o,
                Err(crate::Error::Provider(msg)) if msg.starts_with("mcp-auth-required") => {
                    // One refresh attempt, then one retry — bounded, no loops.
                    let refreshed = self
                        .refresh
                        .as_ref()
                        .and_then(|r| refresh_access_token(r).ok());
                    match refreshed {
                        Some(token) => {
                            client.set_bearer(token);
                            client.tools_call(&self.tool, args)?
                        }
                        None => return Err(crate::Error::Provider(
                            "mcp server rejected the token (401) and no refresh was possible — \
                             re-grant the connector to re-authorize"
                                .into(),
                        )),
                    }
                }
                Err(e) => return Err(e),
            };
        if outcome.is_error {
            Ok(format!("TOOL ERROR (self-correctable): {}", outcome.text))
        } else {
            Ok(outcome.text)
        }
    }
}

/// OAuth refresh-token grant (public client shape). Returns the new access
/// token; the refreshed session lives for this run only — the durable seed
/// stays sealed in the manifest.
fn refresh_access_token(oauth: &Value) -> Result<String, crate::Error> {
    let get = |k: &str| {
        oauth
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| crate::Error::Provider(format!("oauth credential missing {k}")))
    };
    let refresh_token = get("refresh_token")?;
    let token_endpoint = get("token_endpoint")?;
    let client_id = get("client_id")?;
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("client_id", client_id.to_string()),
    ];
    if let Some(resource) = oauth.get("resource").and_then(Value::as_str) {
        form.push(("resource", resource.to_string()));
    }
    let resp = reqwest::blocking::Client::new()
        .post(token_endpoint)
        .form(&form)
        .send()
        .map_err(|e| crate::Error::Provider(format!("oauth refresh: {e}")))?;
    let v: Value = resp
        .json()
        .map_err(|e| crate::Error::Provider(format!("oauth refresh body: {e}")))?;
    v.get("access_token")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| crate::Error::Provider(format!("oauth refresh refused: {v}")))
}
