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
        .route("/api/agents/{npub}/manifest", get(get_manifest))
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
