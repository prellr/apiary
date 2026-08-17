//! apiary-hostd — the host daemon (SPEC §2). REST for governance reads and
//! writes, an AG-UI-compatible SSE stream for live runs, Buzz membership
//! operations with managed listeners, NIP-98 auth, and the cockpit served
//! at /. Custody never leaves this process: clients get JSON about the
//! agent, never key material.
//!
//! This crate is BOTH a library and a binary: the `apiary-hostd` daemon and
//! the Tauri desktop app build the same router — the GUI is a client
//! (SPEC §2), never a second implementation.

pub mod agui;
pub mod events;
pub mod nip98;
pub mod ops;
pub mod routines;

use apiary_core::{
    ceremony, custody::Custody, keystore::Keystore, log::EpisodicLog, manifest::Manifest,
};
use axum::{
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use nostr::prelude::PublicKey;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

pub struct AppState {
    pub home: PathBuf,
    /// Unlockable at runtime (GUI unlock screen) — None means locked:
    /// reads work, anything needing key material refuses.
    pub passphrase: std::sync::RwLock<Option<String>>,
    pub auth: AuthMode,
    /// Canonical origin for exact NIP-98 URL matching.
    pub origin: String,
    /// HOST administrators (nip98 mode): only these keys may perform
    /// host-scoped operations — founding/importing agents, editing the
    /// connector library, locking/unlocking. Per-agent operations stay
    /// governor-bound to that agent's suspend keys; this list is the
    /// authority over the HOST itself (its keystore slots, its inference
    /// credentials, its configuration). Empty in nip98 mode = host-scoped
    /// operations refuse, loudly.
    pub admins: Vec<nostr::prelude::PublicKey>,
    /// Per-launch bearer token (desktop mode). When set, EVERY request must
    /// present it — the desktop webview gets it in its boot URL, so other
    /// local processes cannot drive the embedded daemon.
    pub token: Option<String>,
    /// Managed Buzz mention listeners, one per agent.
    pub listeners: std::sync::Mutex<std::collections::HashMap<String, ops::AgentPresence>>,
    /// In-flight OAuth grants, keyed by the `state` parameter.
    pub pending_oauth: std::sync::Mutex<std::collections::HashMap<String, ops::PendingOauth>>,
    /// Last supervisor outcome per agent (contested lease, failed start…),
    /// surfaced by the listener status endpoint.
    pub supervisor_notes: std::sync::Mutex<std::collections::HashMap<String, String>>,
    /// Decrypted agent keys, cached while UNLOCKED so a run does not pay
    /// NIP-49 scrypt (seconds in debug builds) every time. Same trust
    /// posture as holding the passphrase, which derives exactly these;
    /// cleared on lock. Keyed by npub.
    pub admitted: std::sync::Mutex<std::collections::HashMap<String, nostr::prelude::Keys>>,
}

impl AppState {
    pub fn passphrase_clone(&self) -> Option<String> {
        self.passphrase.read().ok().and_then(|g| g.clone())
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum AuthMode {
    Open,
    Nip98,
}

pub type App = Arc<AppState>;

/// The one router. The daemon binary and the desktop app both serve this.
pub fn build_router(state: App) -> Router {
    Router::new()
        .route("/", get(cockpit))
        .route("/app.js", get(cockpit_js))
        .route("/api/status", get(ops::status))
        .route("/api/unlock", post(ops::unlock))
        .route("/api/lock", post(ops::lock))
        .route("/api/key", get(ops::key_normalize))
        .route(
            "/api/connectors",
            get(ops::connectors_get).put(ops::connectors_put),
        )
        .route("/api/connectors/discover", post(ops::connectors_discover))
        .route("/api/host/pick-folder", post(ops::pick_folder))
        .route("/api/events", get(events::events))
        .route(
            "/api/agents/{npub}/connectors/{name}/discover",
            post(ops::agent_connector_discover),
        )
        .route(
            "/api/agents/{npub}/connectors/{kind}/allowed_tools",
            post(ops::connector_set_allowed_tools),
        )
        .route(
            "/api/agents/{npub}/connectors/{kind}/caps",
            post(ops::connector_patch_caps),
        )
        .route("/api/agents", get(list_agents))
        .route("/api/agents/found", post(found_agent))
        .route("/api/agents/import", post(ops::import_agent))
        .route("/api/agents/{npub}/export", post(ops::export_agent))
        .route(
            "/api/agents/{npub}/manifest",
            get(get_manifest).put(put_manifest),
        )
        .route("/api/agents/{npub}/ratify", post(ratify_agent))
        .route("/api/agents/{npub}/ratify/export", post(ops::ratify_export))
        .route("/api/agents/{npub}/ratify/import", post(ops::ratify_import))
        .route("/api/agents/{npub}/log", get(get_log))
        .route("/api/agents/{npub}/log/publish", post(ops::log_publish))
        .route("/api/agents/{npub}/log/remote", get(ops::log_remote))
        .route("/api/agents/{npub}/run", post(agui::run_stream))
        .route("/api/agents/{npub}/spend", get(ops::spend_status))
        .route(
            "/api/agents/{npub}/credential/seal",
            post(ops::credential_seal),
        )
        .route(
            "/api/agents/{npub}/credential/open",
            post(ops::credential_open),
        )
        .route("/api/agents/{npub}/buzz/channels", get(ops::buzz_channels))
        .route("/api/agents/{npub}/buzz/read", get(ops::buzz_read))
        .route("/api/agents/{npub}/buzz/post", post(ops::buzz_post))
        .route("/api/agents/{npub}/buzz/profile", post(ops::buzz_profile))
        .route("/api/agents/{npub}/buzz/join", post(ops::buzz_join))
        .route("/api/agents/{npub}/active", post(ops::set_active))
        .route("/api/agents/{npub}/connectors", post(ops::connector_grant))
        .route(
            "/api/agents/{npub}/connectors/oauth",
            post(ops::oauth_start),
        )
        .route("/oauth/callback", get(ops::oauth_callback))
        .route("/api/agents/{npub}/name", post(ops::rename_agent))
        .route("/api/agents/{npub}/proposal", get(routines::get_proposal))
        .route(
            "/api/agents/{npub}/proposal/{decision}",
            post(routines::decide_proposal),
        )
        .route("/api/agents/{npub}/routines", get(routines::list_routines))
        .route(
            "/api/agents/{npub}/routines/{name}/run",
            post(routines::run_routine_now),
        )
        .route(
            "/api/agents/{npub}/routines/{name}/{action}",
            post(routines::pause_routine),
        )
        .route("/api/agents/{npub}/lease", get(ops::lease_status))
        .route(
            "/api/agents/{npub}/lease/takeover",
            post(ops::lease_takeover),
        )
        .route(
            "/api/agents/{npub}/connectors/{kind}",
            axum::routing::delete(ops::connector_revoke),
        )
        .route("/api/agents/{npub}/presence", post(ops::presence_declare))
        .route(
            "/api/agents/{npub}/presence/{kind}",
            axum::routing::delete(ops::presence_revoke),
        )
        .route(
            "/api/agents/{npub}/listener",
            get(ops::listener_status).delete(ops::listener_stop),
        )
        .with_state(state)
}

/// Restrictive CSP: no inline script, no external anything. Rendering uses
/// textContent throughout (see cockpit.js) — the CSP is the backstop.
const CSP: &str =
    "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'";

async fn cockpit() -> impl IntoResponse {
    (
        [("content-security-policy", CSP)],
        Html(include_str!("cockpit.html")),
    )
}

async fn cockpit_js() -> impl IntoResponse {
    (
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("content-security-policy", CSP),
        ],
        include_str!("cockpit.js"),
    )
}

pub fn err(
    status: StatusCode,
    msg: impl std::fmt::Display,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(json!({"ok": false, "error": msg.to_string()})))
}

fn normalize(npub: &str) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let pk =
        apiary_core::identity::parse_npub(npub).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
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

pub fn load_manifest(
    dir: &std::path::Path,
) -> Result<(String, Manifest), (StatusCode, Json<serde_json::Value>)> {
    let raw = std::fs::read_to_string(dir.join("manifest.yaml"))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let m = Manifest::from_yaml(&raw).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((raw, m))
}

pub fn suspend_pks(manifest: &Manifest) -> Vec<PublicKey> {
    manifest
        .governance
        .suspend_keys
        .iter()
        .filter_map(|k| apiary_core::identity::parse_npub(k).ok())
        .collect()
}

fn ratified(dir: &std::path::Path, npub: &str, raw: &str, manifest: &Manifest) -> bool {
    let Ok(agent_pk) = apiary_core::identity::parse_npub(npub) else {
        return false;
    };
    ceremony::is_ratified(
        &EpisodicLog::open(dir),
        raw,
        &agent_pk,
        &suspend_pks(manifest),
    )
    .unwrap_or(false)
}

fn path_and_query(uri: &axum::http::Uri) -> String {
    uri.path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| uri.path().to_string())
}

async fn list_agents(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let signer = match nip98::check(&state, &headers, "GET", &path_and_query(&uri), None) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let ks = match Keystore::open(&state.home) {
        Ok(k) => k,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let mut agents = Vec::new();
    for npub in ks.list().unwrap_or_default() {
        let dir = ks.agent_dir(&npub);
        let name = std::fs::read_to_string(dir.join("name")).ok();
        let Ok((raw, m)) = load_manifest(&dir) else {
            continue;
        };
        // In nip98 mode the roster shows only agents the signer governs.
        if nip98::authorize_governor(&state, signer, &suspend_pks(&m)).is_err() {
            continue;
        }
        let entries = EpisodicLog::open(&dir)
            .read_all()
            .map(|v| v.len())
            .unwrap_or(0);
        agents.push(json!({
            "npub": npub,
            "name": name,
            "ratified": ratified(&dir, &npub, &raw, &m),
            "log_entries": entries,
            "active": ops::is_active(&dir),
            "declared_channels": m.presence.channels.keys().cloned().collect::<Vec<_>>(),
        }));
    }
    Json(json!({"ok": true, "agents": agents})).into_response()
}

async fn get_manifest(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let signer = match nip98::check(&state, &headers, "GET", &path_and_query(&uri), None) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let (_ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match load_manifest(&dir) {
        Ok((raw, m)) => {
            if let Err(e) = nip98::authorize_governor(&state, signer, &suspend_pks(&m)) {
                return e.into_response();
            }
            Json(json!({
                "ok": true,
                "npub": npub,
                "yaml": raw,
                "manifest": serde_json::to_value(&m).unwrap_or_default(),
                "ratified": ratified(&dir, &npub, &raw, &m),
                "manifest_sha256": ceremony::manifest_hash(&raw),
            }))
            .into_response()
        }
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
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let signer = match nip98::check(&state, &headers, "GET", &path_and_query(&uri), None) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let (_ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match load_manifest(&dir) {
        Ok((_, m)) => {
            if let Err(e) = nip98::authorize_governor(&state, signer, &suspend_pks(&m)) {
                return e.into_response();
            }
        }
        Err(e) => return e.into_response(),
    }
    let log = EpisodicLog::open(&dir);
    let chain = log
        .verify()
        .map(|n| json!({"valid": true, "entries": n}))
        .unwrap_or_else(|e| json!({"valid": false, "error": e.to_string()}));
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
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let signer = match nip98::check(
        &state,
        &headers,
        "PUT",
        &path_and_query(&uri),
        Some(&raw_body),
    ) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let body: PutManifestBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let (_ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    // Governorship is checked against the CURRENT constitution — the one
    // being amended — so a stranger cannot grant themselves authority by
    // writing a manifest that names them.
    match load_manifest(&dir) {
        Ok((_, current)) => {
            if let Err(e) = nip98::authorize_governor(&state, signer, &suspend_pks(&current)) {
                return e.into_response();
            }
        }
        Err(e) => return e.into_response(),
    }
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
        return err(
            StatusCode::BAD_REQUEST,
            "manifest identity.npub must match the agent",
        )
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
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let signer = match nip98::check(
        &state,
        &headers,
        "POST",
        &path_and_query(&uri),
        Some(&raw_body),
    ) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let body: RatifyBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
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
    let listed = suspend_pks(&manifest);
    let ratifier_pk = match apiary_core::identity::parse_npub(&as_key) {
        Ok(pk) if listed.contains(&pk) => pk,
        Ok(_) => {
            return err(
                StatusCode::FORBIDDEN,
                "ratifier is not a listed suspend key",
            )
            .into_response()
        }
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    // A host-held human key signs ONLY for the person who proved possession
    // of that same key: in nip98 mode the request signer must BE the
    // ratifier. (Open mode is local trust — same as holding the keystore.)
    if state.auth == AuthMode::Nip98 && signer != Some(ratifier_pk) {
        return err(
            StatusCode::FORBIDDEN,
            "ratification must be signed by the ratifying key itself (as == request signer)",
        )
        .into_response();
    }
    let pass = match state.passphrase_clone() {
        Some(p) => p,
        None => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "keystore is locked — unlock with the passphrase first",
            )
            .into_response()
        }
    };
    let (agent_keys, human_keys) = match (ks.load(&npub, &pass), ks.load(&as_key, &pass)) {
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
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let signer = match nip98::check(
        &state,
        &headers,
        "POST",
        &path_and_query(&uri),
        Some(&raw_body),
    ) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = nip98::authorize_admin(&state, signer) {
        return e.into_response();
    }
    let body: FoundBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if body.suspend_keys.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "at least one human suspend key is required",
        )
        .into_response();
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
    // The founder must govern what they found: in nip98 mode the request
    // signer must be among the new agent's suspend keys.
    if state.auth == AuthMode::Nip98 {
        let listed = suspend
            .iter()
            .filter_map(|k| apiary_core::identity::parse_npub(k).ok())
            .collect::<Vec<_>>();
        if let Err(e) = nip98::authorize_governor(&state, signer, &listed) {
            return e.into_response();
        }
    }
    let pass = match state.passphrase_clone() {
        Some(p) => p,
        None => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "keystore is locked — unlock with the passphrase first",
            )
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
    if let Err(e) = ks.store(&keys, &pass) {
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
            .complete("claude-opus-5", system, &prompt, &[], 8192)
            .map_err(|e| e.to_string())?;
        if completion.outcome != "ok" {
            return Err(format!("draft stopped: {}", completion.outcome));
        }
        Ok(completion
            .text
            .trim()
            .trim_start_matches("```yaml")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
            .to_string())
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
        .passphrase_clone()
        .ok_or("keystore is locked — unlock with the passphrase first")?;
    let cached = state
        .admitted
        .lock()
        .ok()
        .and_then(|m| m.get(npub).cloned());
    let keys = match cached {
        Some(k) => k,
        None => {
            let k = ks.load(npub, &pass).map_err(|e| e.to_string())?;
            if let Ok(mut m) = state.admitted.lock() {
                m.insert(npub.to_string(), k.clone());
            }
            k
        }
    };
    let mut custody = Custody::new();
    let handle = custody.admit(keys);
    Ok((custody, handle))
}
