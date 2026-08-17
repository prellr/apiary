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
pub const BOUND_KINDS: &[&str] = &[
    "nostr-publish",
    "mock-echo",
    "mcp",
    "obsidian",
    "markdown-vault",
];

/// Build the agent's connector set from its manifest. Unknown kinds are an
/// error, not a skip — a manifest declaring a capability the host can't
/// bind should fail loudly at run start, not silently at dispatch.
pub fn bind_connectors(
    manifest: &Manifest,
    custody: &Custody,
    agent: &AgentHandle,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    bind_connectors_in(manifest, custody, agent, None)
}

/// With the agent dir known, the agent also gets the PROPOSE tools —
/// harmless by construction (a proposal is never enacted by the agent).
pub fn bind_connectors_in(
    manifest: &Manifest,
    custody: &Custody,
    agent: &AgentHandle,
    agent_dir: Option<&std::path::Path>,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    let mut out: Vec<Box<dyn Connector>> = Vec::new();
    if let Some(dir) = agent_dir {
        out.push(Box::new(crate::proposal::ProposeRoutine {
            agent_dir: dir.to_path_buf(),
            manifest: manifest.clone(),
        }));
        out.push(Box::new(crate::proposal::ProposeAmendment {
            agent_dir: dir.to_path_buf(),
            manifest: manifest.clone(),
        }));
    }
    for entry in &manifest.connectors {
        match entry.kind.as_str() {
            "mcp" => out.extend(bind_mcp(entry, custody, agent)?),
            "obsidian" => out.extend(bind_vault(entry, true)?),
            "markdown-vault" => out.extend(bind_vault(entry, false)?),
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
    // Presence-derived tools: a channel the agent LIVES on is also a place
    // it may speak first. Same sealed token, same allowlist — declaring
    // presence was the ratified act, so no separate grant exists to forget.
    if let Some(tg) = manifest.presence.channel("telegram") {
        if let Some(cred) = &tg.credential {
            let speaker = crate::speak::speak_slot(manifest).and_then(|slot| {
                let credential = slot
                    .credential
                    .as_ref()
                    .and_then(|b| custody.open(agent, b).ok());
                crate::speak::bind_speaker(manifest, credential)
            });
            out.push(Box::new(crate::telegram::TelegramSend {
                credential: cred.clone(),
                allowed_chats: tg.list_config("allowed_chats"),
                speaker,
            }));
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

// ---------------------------------------------------------------- vaults

/// Bind an `obsidian` / `markdown-vault` connector: named markdown
/// folders (Obsidian vaults, checked-out KB repos, plain note dirs) as
/// tools. Caps:
///
/// ```yaml
/// - type: markdown-vault          # or obsidian (adds tags/frontmatter/wikilinks)
///   caps:
///     vaults:
///       - {name: kb, path: /Users/me/repos/winery-kb/kb}
///       - {name: notes, path: ~/notes}
///     write: false                # write/append tools exist ONLY when true
/// ```
///
/// Reads are path-jailed to each vault root (traversal and symlink
/// escapes refused). Note content returned to the model is DATA under the
/// provenance rule, like every tool result.
fn bind_vault(
    entry: &apiary_core::manifest::Connector,
    obsidian: bool,
) -> Result<Vec<Box<dyn Connector>>, crate::Error> {
    let vaults: Vec<(String, std::path::PathBuf)> = entry
        .caps
        .get("vaults")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| {
                    Some((
                        v.get("name")?.as_str()?.to_string(),
                        v.get("path")?.as_str()?.to_string(),
                    ))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
        .into_iter()
        .map(|(name, path)| crate::vault::open_root(&path).map(|root| (name, root)))
        .collect::<Result<_, _>>()?;
    if vaults.is_empty() {
        return Err(crate::Error::Provider(
            "vault connector requires caps.vaults: [{name, path}, …]".into(),
        ));
    }
    let write = entry
        .caps
        .get("write")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let kind = if obsidian { "obsidian" } else { "vault" };
    let vault_names: Vec<String> = vaults.iter().map(|(n, _)| n.clone()).collect();
    let shared = std::sync::Arc::new(vaults);
    let mut out: Vec<Box<dyn Connector>> = vec![
        Box::new(VaultSearch {
            kind,
            obsidian,
            vaults: shared.clone(),
            names: vault_names.clone(),
        }),
        Box::new(VaultRead {
            kind,
            obsidian,
            vaults: shared.clone(),
            names: vault_names.clone(),
        }),
    ];
    if write {
        out.push(Box::new(VaultWrite {
            kind,
            vaults: shared,
            names: vault_names,
        }));
    }
    Ok(out)
}

type Vaults = std::sync::Arc<Vec<(String, std::path::PathBuf)>>;

fn vault_root<'a>(
    vaults: &'a Vaults,
    name: Option<&str>,
) -> Result<&'a (String, std::path::PathBuf), crate::Error> {
    match name {
        None if vaults.len() == 1 => Ok(&vaults[0]),
        None => Err(crate::Error::Provider(format!(
            "several vaults are granted — name one: {}",
            vaults
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        Some(n) => vaults.iter().find(|(name, _)| name == n).ok_or_else(|| {
            crate::Error::Provider(format!(
                "no vault named '{n}' (granted: {})",
                vaults
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }),
    }
}

struct VaultSearch {
    kind: &'static str,
    obsidian: bool,
    vaults: Vaults,
    names: Vec<String>,
}

impl Connector for VaultSearch {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: format!("{}_search", self.kind),
            description: format!(
                "Search the granted markdown knowledge vaults ({}) by title{}, and content. \
                 Returns matching notes with paths for {}_read.",
                self.names.join(", "),
                if self.obsidian { ", tags" } else { "" },
                self.kind
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "vault": {"type": "string", "description": "vault name (optional when only one is granted)"},
                },
                "required": ["query"],
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::Error::Provider("query is required".into()))?;
        let named = args.get("vault").and_then(|v| v.as_str());
        let targets: Vec<&(String, std::path::PathBuf)> = match named {
            Some(_) => vec![vault_root(&self.vaults, named)?],
            None => self.vaults.iter().collect(),
        };
        let mut out = Vec::new();
        for (name, root) in targets {
            for hit in crate::vault::search(root, query, self.obsidian, 12)? {
                out.push(json!({
                    "vault": name,
                    "path": hit.rel,
                    "title": hit.title,
                    "matched": hit.matched,
                    "snippet": hit.snippet,
                }));
            }
        }
        if out.is_empty() {
            return Ok(format!("no notes match '{query}'"));
        }
        Ok(serde_json::to_string(&out)?)
    }
}

struct VaultRead {
    kind: &'static str,
    obsidian: bool,
    vaults: Vaults,
    names: Vec<String>,
}

impl Connector for VaultRead {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: format!("{}_read", self.kind),
            description: format!(
                "Read one note (by vault-relative path) from the granted vaults ({}).{}",
                self.names.join(", "),
                if self.obsidian {
                    " Returns frontmatter tags and outgoing [[wikilinks]] alongside the body."
                } else {
                    ""
                }
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "vault": {"type": "string", "description": "vault name (optional when only one is granted)"},
                },
                "required": ["path"],
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let rel = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::Error::Provider("path is required".into()))?;
        let (name, root) = vault_root(&self.vaults, args.get("vault").and_then(|v| v.as_str()))?;
        let content = crate::vault::read_note(root, rel)?;
        if self.obsidian {
            let t = crate::vault::tags(&content);
            let links = crate::vault::wikilinks(&content);
            let (_, body) = crate::vault::split_frontmatter(&content);
            Ok(json!({
                "vault": name,
                "path": rel,
                "tags": t,
                "wikilinks": links,
                "body": body,
            })
            .to_string())
        } else {
            Ok(json!({"vault": name, "path": rel, "body": content}).to_string())
        }
    }
}

struct VaultWrite {
    kind: &'static str,
    vaults: Vaults,
    names: Vec<String>,
}

impl Connector for VaultWrite {
    fn def(&self) -> ToolDef {
        ToolDef {
            name: format!("{}_write", self.kind),
            description: format!(
                "Write or append a markdown note in the granted vaults ({}). \
                 The manifest's write cap authorized this — use it sparingly \
                 and keep humans' notes intact (prefer append).",
                self.names.join(", ")
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "vault-relative path ending in .md"},
                    "content": {"type": "string"},
                    "append": {"type": "boolean", "description": "append instead of overwrite (default true)"},
                    "vault": {"type": "string"},
                },
                "required": ["path", "content"],
            }),
        }
    }

    fn execute(
        &self,
        _custody: &Custody,
        _agent: &AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let rel = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::Error::Provider("path is required".into()))?;
        // Ordered defenses (review finding: symlink escapes + create-
        // before-check): reject absolute paths and traversal LEXICALLY
        // first, verify the deepest EXISTING ancestor canonicalizes into
        // the jail BEFORE creating anything, re-verify the parent after
        // creation, and refuse to write through a symlink target.
        let rel_path = std::path::Path::new(rel);
        if rel_path.is_absolute()
            || !rel.ends_with(".md")
            || rel_path
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(crate::Error::Provider(
                "path must be a plain vault-relative .md file (no traversal, no absolute paths)"
                    .into(),
            ));
        }
        let content = args
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::Error::Provider("content is required".into()))?;
        let append = args.get("append").and_then(|v| v.as_bool()).unwrap_or(true);
        let (name, root) = vault_root(&self.vaults, args.get("vault").and_then(|v| v.as_str()))?;
        let target = root.join(rel_path);
        let parent = target
            .parent()
            .ok_or_else(|| crate::Error::Provider("bad path".into()))?;
        // Deepest existing ancestor must live in the jail BEFORE mkdir —
        // a symlinked intermediate directory would otherwise carry the
        // new directories (and the file) outside the vault.
        let mut probe = parent.to_path_buf();
        while !probe.exists() {
            probe = match probe.parent() {
                Some(p) => p.to_path_buf(),
                None => return Err(crate::Error::Provider("bad path".into())),
            };
        }
        let canon_probe = probe
            .canonicalize()
            .map_err(|e| crate::Error::Provider(e.to_string()))?;
        if !canon_probe.starts_with(root) {
            return Err(crate::Error::Provider(format!(
                "'{rel}' escapes the vault — refused"
            )));
        }
        std::fs::create_dir_all(parent).map_err(|e| crate::Error::Provider(e.to_string()))?;
        let canon_parent = parent
            .canonicalize()
            .map_err(|e| crate::Error::Provider(e.to_string()))?;
        if !canon_parent.starts_with(root) {
            return Err(crate::Error::Provider(format!(
                "'{rel}' escapes the vault — refused"
            )));
        }
        // Never write THROUGH a symlink: an existing evil.md → /etc/…
        // must not receive the append/overwrite.
        let existed = match std::fs::symlink_metadata(&target) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(crate::Error::Provider(format!(
                    "'{rel}' is a symlink — refused"
                )))
            }
            Ok(_) => true,
            Err(_) => false,
        };
        use std::io::Write;
        if append && existed {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&target)
                .map_err(|e| crate::Error::Provider(e.to_string()))?;
            writeln!(f, "\n{content}").map_err(|e| crate::Error::Provider(e.to_string()))?;
        } else {
            std::fs::write(&target, content).map_err(|e| crate::Error::Provider(e.to_string()))?;
        }
        let _ = self.kind;
        Ok(
            json!({"vault": name, "path": rel, "written": true, "appended": append && existed})
                .to_string(),
        )
    }
}
