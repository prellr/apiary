//! apiary-hostd — the host daemon (SPEC §2). REST for governance reads,
//! an AG-UI-compatible SSE stream for live runs, NIP-98 auth, and the
//! cockpit served at /. Custody never leaves this process: clients get
//! JSON about the agent, never key material.

mod agui;
mod nip98;

use apiary_core::{ceremony, custody::Custody, keystore::Keystore, log::EpisodicLog, manifest::Manifest};
use axum::{
    extract::{Path as AxPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "apiary-hostd", version, about = "Apiary host daemon")]
struct Args {
    /// State directory (keys, manifests).
    #[arg(long, env = "APIARY_HOME", default_value_os_t = default_home())]
    home: PathBuf,
    /// Dev-keystore passphrase; required to run tasks.
    #[arg(long, env = "APIARY_PASSPHRASE", hide_env_values = true)]
    passphrase: Option<String>,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:7777")]
    bind: String,
    /// Auth mode: "open" (localhost dev) or "nip98" (signed requests).
    #[arg(long, default_value = "open")]
    auth: String,
}

fn default_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".apiary")
}

pub struct AppState {
    pub home: PathBuf,
    pub passphrase: Option<String>,
    pub auth: AuthMode,
}

#[derive(Clone, Copy, PartialEq)]
pub enum AuthMode {
    Open,
    Nip98,
}

type App = Arc<AppState>;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let auth = match args.auth.as_str() {
        "nip98" => AuthMode::Nip98,
        _ => {
            eprintln!("auth=open: every local process can drive this daemon; use --auth nip98 beyond localhost dev");
            AuthMode::Open
        }
    };
    let state: App = Arc::new(AppState {
        home: args.home.clone(),
        passphrase: args.passphrase.clone(),
        auth,
    });
    let app = Router::new()
        .route("/", get(cockpit))
        .route("/api/agents", get(list_agents))
        .route("/api/agents/found", post(found_agent))
        .route("/api/agents/{npub}/manifest", get(get_manifest).put(put_manifest))
        .route("/api/agents/{npub}/ratify", post(ratify_agent))
        .route("/api/agents/{npub}/log", get(get_log))
        .route("/api/agents/{npub}/run", post(agui::run_stream))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&args.bind).await.expect("bind");
    println!("apiary-hostd listening on http://{}", args.bind);
    axum::serve(listener, app).await.expect("serve");
}

async fn cockpit() -> Html<&'static str> {
    Html(include_str!("cockpit.html"))
}

pub fn err(status: StatusCode, msg: impl std::fmt::Display) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(json!({"ok": false, "error": msg.to_string()})))
}

fn normalize(npub: &str) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let pk = apiary_core::identity::parse_npub(npub)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    apiary_core::identity::to_npub(&pk).map_err(|e| err(StatusCode::BAD_REQUEST, e))
}

/// Shared per-request context: keystore + validated agent dir.
pub fn agent_ctx(
    state: &AppState,
    npub: &str,
) -> Result<(Keystore, String, PathBuf), (StatusCode, Json<serde_json::Value>)> {
    let ks = Keystore::open(&state.home).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let npub = normalize(npub)?;
    let dir = ks.agent_dir(&npub);
    if !dir.join("manifest.yaml").exists() {
        return Err(err(StatusCode::NOT_FOUND, format!("no agent {npub}")));
    }
    Ok((ks, npub, dir))
}

pub fn load_manifest(dir: &std::path::Path) -> Result<(String, Manifest), (StatusCode, Json<serde_json::Value>)> {
    let raw = std::fs::read_to_string(dir.join("manifest.yaml"))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let m = Manifest::from_yaml(&raw).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((raw, m))
}

fn ratified(dir: &std::path::Path, raw: &str, manifest: &Manifest) -> bool {
    let Ok(keys) = manifest
        .governance
        .suspend_keys
        .iter()
        .map(|k| apiary_core::identity::parse_npub(k))
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    ceremony::is_ratified(&EpisodicLog::open(dir), raw, &keys).unwrap_or(false)
}

async fn list_agents(State(state): State<App>, headers: axum::http::HeaderMap) -> impl IntoResponse {
    if let Err(e) = nip98::check(&state, &headers, "/api/agents", "GET") {
        return e.into_response();
    }
    let ks = match Keystore::open(&state.home) {
        Ok(k) => k,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let mut agents = Vec::new();
    for npub in ks.list().unwrap_or_default() {
        let dir = ks.agent_dir(&npub);
        let name = std::fs::read_to_string(dir.join("name")).ok();
        let (rat, entries) = match load_manifest(&dir) {
            Ok((raw, m)) => (
                ratified(&dir, &raw, &m),
                EpisodicLog::open(&dir).read_all().map(|v| v.len()).unwrap_or(0),
            ),
            Err(_) => (false, 0),
        };
        agents.push(json!({
            "npub": npub, "name": name, "ratified": rat, "log_entries": entries,
        }));
    }
    Json(json!({"ok": true, "agents": agents})).into_response()
}

async fn get_manifest(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = nip98::check(&state, &headers, &format!("/api/agents/{npub}/manifest"), "GET") {
        return e.into_response();
    }
    let (_ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match load_manifest(&dir) {
        Ok((raw, m)) => Json(json!({
            "ok": true,
            "npub": npub,
            "yaml": raw,
            "manifest": serde_json::to_value(&m).unwrap_or_default(),
            "ratified": ratified(&dir, &raw, &m),
            "manifest_sha256": ceremony::manifest_hash(&raw),
        }))
        .into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
struct LogQuery {
    #[serde(default = "default_tail")]
    tail: usize,
}
fn default_tail() -> usize {
    50
}

async fn get_log(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    Query(q): Query<LogQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = nip98::check(&state, &headers, &format!("/api/agents/{npub}/log"), "GET") {
        return e.into_response();
    }
    let (_ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let log = EpisodicLog::open(&dir);
    let chain = log.verify().map(|n| json!({"valid": true, "entries": n})).unwrap_or_else(
        |e| json!({"valid": false, "error": e.to_string()}),
    );
    let entries: Vec<serde_json::Value> = log
        .tail(q.tail)
        .unwrap_or_default()
        .iter()
        .map(|e| {
            json!({
                "id": e.id.to_hex(),
                "at": e.created_at.as_secs(),
                "signer": e.pubkey.to_hex(),
                "body": EpisodicLog::parse_body(e).ok(),
            })
        })
        .collect();
    Json(json!({"ok": true, "npub": npub, "chain": chain, "entries": entries})).into_response()
}

#[derive(serde::Deserialize)]
struct PutManifestBody {
    yaml: String,
}

/// Amend the constitution. Validation is structural; the governance effect
/// is automatic: a changed hash means the ratification no longer matches,
/// so the agent refuses to run until re-ratified. Amendments are cheap;
/// unratified amendments are inert.
async fn put_manifest(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<PutManifestBody>,
) -> impl IntoResponse {
    if let Err(e) = nip98::check(&state, &headers, &format!("/api/agents/{npub}/manifest"), "PUT") {
        return e.into_response();
    }
    let (_ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let manifest = match Manifest::from_yaml(&body.yaml) {
        Ok(m) => m,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    // The manifest's identity must stay the agent's own.
    let identity_ok = apiary_core::identity::parse_npub(&manifest.identity.npub)
        .ok()
        .and_then(|pk| apiary_core::identity::to_npub(&pk).ok())
        .is_some_and(|n| n == npub);
    if !identity_ok {
        return err(StatusCode::BAD_REQUEST, "manifest identity.npub must match the agent")
            .into_response();
    }
    if let Err(e) = std::fs::write(dir.join("manifest.yaml"), &body.yaml) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "manifest_sha256": ceremony::manifest_hash(&body.yaml),
        "ratified": false,
        "note": "amendment saved — re-ratify before the agent runs again",
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct RatifyBody {
    /// Ratifying human's key (npub or hex) — keystore-held, listed in suspend_keys.
    r#as: String,
}

async fn ratify_agent(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RatifyBody>,
) -> impl IntoResponse {
    if let Err(e) = nip98::check(&state, &headers, &format!("/api/agents/{npub}/ratify"), "POST") {
        return e.into_response();
    }
    let (ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let (raw, manifest) = match load_manifest(&dir) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let as_key = match normalize(&body.r#as) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let listed = manifest
        .governance
        .suspend_keys
        .iter()
        .filter_map(|k| apiary_core::identity::parse_npub(k).ok())
        .collect::<Vec<_>>();
    let ratifier_pk = match apiary_core::identity::parse_npub(&as_key) {
        Ok(pk) if listed.contains(&pk) => pk,
        Ok(_) => {
            return err(StatusCode::FORBIDDEN, "ratifier is not a listed suspend key").into_response()
        }
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let _ = ratifier_pk;
    let pass = match state.passphrase.as_deref() {
        Some(p) => p,
        None => {
            return err(StatusCode::SERVICE_UNAVAILABLE, "daemon has no passphrase; ratification disabled")
                .into_response()
        }
    };
    let (agent_keys, human_keys) = match (ks.load(&npub, pass), ks.load(&as_key, pass)) {
        (Ok(a), Ok(h)) => (a, h),
        (Err(e), _) | (_, Err(e)) => return err(StatusCode::UNAUTHORIZED, e).into_response(),
    };
    let mut custody = Custody::new();
    let agent_handle = custody.admit(agent_keys);
    let human_handle = custody.admit(human_keys);
    let log = EpisodicLog::open(&dir);
    let result = ceremony::sign_manifest(&custody, &agent_handle, &log, &raw)
        .and_then(|s| ceremony::ratify(&custody, &human_handle, &log, &npub, &raw).map(|r| (s, r)));
    match result {
        Ok((signed, ratified)) => Json(json!({
            "ok": true,
            "npub": npub,
            "ratified_by": as_key,
            "manifest_sha256": ceremony::manifest_hash(&raw),
            "events": {"signed": signed.id.to_hex(), "ratified": ratified.id.to_hex()},
        }))
        .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct FoundBody {
    name: String,
    /// What this agent is for — the seed of its constitution.
    purpose: String,
    /// Human suspend keys (npub/hex). At least one required.
    suspend_keys: Vec<String>,
    /// "anthropic" to draft the manifest with a model; anything else (or
    /// missing credentials) falls back to the conservative template.
    #[serde(default)]
    draft_with: Option<String>,
}

/// The founding flow (SPEC §12.5, generative-UI-first): generate identity,
/// DRAFT a manifest from the purpose — by a model when available, template
/// otherwise — and return it for human review. Founding is the moment of
/// maximum ignorance: the draft is a hypothesis, not a commitment; nothing
/// runs until ratified.
async fn found_agent(
    State(state): State<App>,
    headers: axum::http::HeaderMap,
    Json(body): Json<FoundBody>,
) -> impl IntoResponse {
    if let Err(e) = nip98::check(&state, &headers, "/api/agents/found", "POST") {
        return e.into_response();
    }
    if body.suspend_keys.is_empty() {
        return err(StatusCode::BAD_REQUEST, "at least one human suspend key is required").into_response();
    }
    let suspend: Vec<String> = match body
        .suspend_keys
        .iter()
        .map(|k| normalize(k).map_err(|(_, e)| e))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match state.passphrase.as_deref() {
        Some(p) => p,
        None => {
            return err(StatusCode::SERVICE_UNAVAILABLE, "daemon has no passphrase; founding disabled")
                .into_response()
        }
    };
    let ks = match Keystore::open(&state.home) {
        Ok(k) => k,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let keys = apiary_core::identity::generate();
    let npub = match apiary_core::identity::to_npub(&keys.public_key()) {
        Ok(n) => n,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(e) = ks.store(&keys, pass) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }

    let template = template_manifest(&npub, &suspend);
    let (yaml, drafted_by) = if body.draft_with.as_deref() == Some("anthropic") {
        match draft_manifest_with_model(&npub, &body.purpose, &suspend, &template).await {
            Ok(y) => (y, "anthropic"),
            Err(e) => {
                eprintln!("founding draft fell back to template: {e}");
                (template.clone(), "template (model draft failed)")
            }
        }
    } else {
        (template.clone(), "template")
    };
    // Whatever drafted it, it must parse and pass invariants — or we fall
    // back to the template rather than storing an invalid constitution.
    let (yaml, drafted_by) = match Manifest::from_yaml(&yaml) {
        Ok(_) => (yaml, drafted_by),
        Err(_) => (template, "template (model draft invalid)"),
    };
    let dir = ks.agent_dir(&npub);
    if let Err(e) = std::fs::write(dir.join("manifest.yaml"), &yaml)
        .and_then(|_| std::fs::write(dir.join("name"), &body.name))
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "name": body.name,
        "yaml": yaml,
        "drafted_by": drafted_by,
        "ratified": false,
        "note": "review the draft, amend as needed, then ratify — nothing runs unratified",
    }))
    .into_response()
}

fn template_manifest(npub: &str, suspend: &[String]) -> String {
    let keys: String = suspend.iter().map(|k| format!("    - {k}\n")).collect();
    format!(
        "manifest_version: 1\n\
         identity:\n  npub: {npub}\n\
         inference:\n\
         - name: workhorse\n  provider: anthropic\n  model: claude-opus-5\n\
         routing:\n  default: workhorse\n\
         connectors: []\n\
         memory:\n  log: local\n  index: local\n\
         governance:\n  suspend_keys:\n{keys}  budgets:\n    tokens_per_day: 100000\n"
    )
}

/// Ask a model to draft the constitution from the purpose statement.
/// The draft is reviewed by a human before anything is ratified — the model
/// proposes, the human disposes.
async fn draft_manifest_with_model(
    npub: &str,
    purpose: &str,
    suspend: &[String],
    template: &str,
) -> Result<String, String> {
    let npub = npub.to_string();
    let purpose = purpose.to_string();
    let suspend = suspend.to_vec();
    let template = template.to_string();
    tokio::task::spawn_blocking(move || {
        let provider = apiary_runtime::inference::AnthropicProvider::from_env()
            .ok_or("no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN in daemon environment")?;
        use apiary_runtime::inference::Provider;
        let system = "You draft founding manifests for Apiary agents. Output ONLY valid YAML, \
                      no fences, no commentary. Constraints: manifest_version 1; identity.npub \
                      exactly as given; suspend_keys exactly as given; connectors only from: \
                      nostr-publish (needs caps.relays list). Budgets conservative. The routing \
                      pool may use providers: anthropic, ollama. Follow the template's shape.";
        let prompt = format!(
            "Template:\n{template}\nAgent npub: {npub}\nSuspend keys: {suspend:?}\n\
             Purpose of this agent: {purpose}\n\nDraft the manifest YAML."
        );
        let completion = provider
            .complete("claude-opus-5", system, &prompt)
            .map_err(|e| e.to_string())?;
        if completion.outcome != "ok" {
            return Err(format!("draft stopped: {}", completion.outcome));
        }
        Ok(completion.text.trim().trim_start_matches("```yaml").trim_start_matches("```").trim_end_matches("```").trim().to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Load an agent's keys into a fresh custody and hand back (custody, handle).
/// Used by the run stream; requires the daemon's passphrase.
pub fn admit_agent(
    state: &AppState,
    ks: &Keystore,
    npub: &str,
) -> Result<(Custody, apiary_core::custody::AgentHandle), String> {
    let pass = state
        .passphrase
        .as_deref()
        .ok_or("daemon started without APIARY_PASSPHRASE; runs are disabled")?;
    let keys = ks.load(npub, pass).map_err(|e| e.to_string())?;
    let mut custody = Custody::new();
    let handle = custody.admit(keys);
    Ok((custody, handle))
}
