//! The rest of the host surface: status/unlock, key tool, spend meter,
//! log publication, credential custody, Buzz membership operations, and
//! managed mention listeners. Everything the CLI can do, the GUI can do —
//! same governance gates, same log entries (SPEC §2: the GUI is a client).

use crate::{agent_ctx, err, load_manifest, nip98, suspend_pks, App, AppState};
use apiary_core::{ceremony, custody::Custody, keystore::Keystore, log::EpisodicLog};
use axum::{
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use nostr::prelude::*;
use serde_json::json;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

type Resp = (StatusCode, Json<serde_json::Value>);

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One running Buzz mention listener. The thread detaches; `stop` is the
/// only control and `done` the only completion signal — no join handles to
/// poison a request path.
pub struct ListenerHandle {
    pub stop: Arc<AtomicBool>,
    pub done: Arc<AtomicBool>,
    pub relay: String,
    pub trigger: String,
    pub started_at: u64,
    pub lines: Arc<Mutex<VecDeque<String>>>,
    /// Hash of the manifest the listener started under. The supervisor
    /// stops the listener when the on-disk manifest diverges — a running
    /// listener must never keep acting under a superseded constitution.
    pub manifest_sha: String,
}

fn push_line(lines: &Mutex<VecDeque<String>>, line: String) {
    if let Ok(mut q) = lines.lock() {
        if q.len() >= 300 {
            q.pop_front();
        }
        q.push_back(format!("[{}] {line}", now_secs()));
    }
}

/// The common request gate: token/NIP-98 check, agent resolution, manifest
/// load, governor authorization. Every per-agent endpoint goes through this.
#[allow(clippy::type_complexity)]
fn gate(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    method: &str,
    uri: &axum::http::Uri,
    body: Option<&[u8]>,
    npub: &str,
) -> Result<
    (
        Keystore,
        String,
        std::path::PathBuf,
        String,
        apiary_core::manifest::Manifest,
    ),
    Resp,
> {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = nip98::check(state, headers, method, &pq, body)?;
    let (ks, npub, dir) = agent_ctx(state, npub)?;
    let (raw, manifest) = load_manifest(&dir)?;
    nip98::authorize_governor(state, signer, &suspend_pks(&manifest))?;
    Ok((ks, npub, dir, raw, manifest))
}

fn require_pass(state: &AppState) -> Result<String, Resp> {
    state.passphrase_clone().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "keystore is locked — unlock with the passphrase first",
        )
    })
}

fn admit(
    ks: &Keystore,
    npub: &str,
    pass: &str,
) -> Result<(Custody, apiary_core::custody::AgentHandle), Resp> {
    let keys = ks
        .load(npub, pass)
        .map_err(|e| err(StatusCode::UNAUTHORIZED, e))?;
    let mut custody = Custody::new();
    let handle = custody.admit(keys);
    Ok((custody, handle))
}

// ---------------------------------------------------------------- status

pub async fn status(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    if let Err(e) = nip98::check(&state, &headers, "GET", &pq, None) {
        return e.into_response();
    }
    let unlocked = state
        .passphrase
        .read()
        .map(|g| g.is_some())
        .unwrap_or(false);
    let agents = Keystore::open(&state.home)
        .and_then(|ks| ks.list())
        .map(|v| v.len())
        .unwrap_or(0);
    let listeners: Vec<serde_json::Value> = state
        .listeners
        .lock()
        .map(|m| {
            m.iter()
                .map(|(npub, l)| {
                    json!({
                        "npub": npub,
                        "relay": l.relay,
                        "running": !l.done.load(Ordering::Relaxed),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Json(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "home": state.home.display().to_string(),
        "auth": match state.auth { crate::AuthMode::Open => "open", crate::AuthMode::Nip98 => "nip98" },
        "token_gated": state.token.is_some(),
        "unlocked": unlocked,
        "agents": agents,
        "listeners": listeners,
        "anthropic_key_present": std::env::var("ANTHROPIC_API_KEY").is_ok()
            || std::env::var("ANTHROPIC_AUTH_TOKEN").is_ok(),
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct UnlockBody {
    passphrase: String,
}

/// Unlock the keystore for this daemon's lifetime. Verified against a real
/// key when one exists — a wrong passphrase is rejected here rather than
/// surfacing later as a confusing decrypt failure mid-operation.
pub async fn unlock(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    if let Err(e) = nip98::check(&state, &headers, "POST", &pq, Some(&raw_body)) {
        return e.into_response();
    }
    let body: UnlockBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if body.passphrase.is_empty() {
        return err(StatusCode::BAD_REQUEST, "empty passphrase").into_response();
    }
    let state2 = state.clone();
    let pass = body.passphrase.clone();
    // NIP-49 scrypt is deliberately slow — off the async runtime.
    let verified = tokio::task::spawn_blocking(move || {
        let ks = Keystore::open(&state2.home).map_err(|e| e.to_string())?;
        let listed = ks.list().map_err(|e| e.to_string())?;
        match listed.first() {
            Some(first) => ks
                .load(first, &pass)
                .map(|_| true)
                .map_err(|e| format!("wrong passphrase? ({e})")),
            // Empty keystore: nothing to verify against; accept and the
            // first founding will set the standard.
            None => Ok(false),
        }
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    match verified {
        Ok(checked) => {
            if let Ok(mut g) = state.passphrase.write() {
                *g = Some(body.passphrase);
            }
            Json(json!({"ok": true, "unlocked": true, "verified_against_key": checked}))
                .into_response()
        }
        Err(e) => err(StatusCode::UNAUTHORIZED, e).into_response(),
    }
}

pub async fn lock(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    if let Err(e) = nip98::check(&state, &headers, "POST", &pq, None) {
        return e.into_response();
    }
    if let Ok(mut g) = state.passphrase.write() {
        *g = None;
    }
    Json(json!({"ok": true, "unlocked": false})).into_response()
}

// ---------------------------------------------------------------- key tool

#[derive(serde::Deserialize)]
pub struct KeyQuery {
    key: String,
}

pub async fn key_normalize(
    State(state): State<App>,
    Query(q): Query<KeyQuery>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    if let Err(e) = nip98::check(&state, &headers, "GET", &pq, None) {
        return e.into_response();
    }
    match apiary_core::identity::parse_npub(&q.key) {
        Ok(pk) => Json(json!({
            "ok": true,
            "npub": apiary_core::identity::to_npub(&pk).unwrap_or_default(),
            "hex": pk.to_hex(),
        }))
        .into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e).into_response(),
    }
}

// ---------------------------------------------------------------- spend

pub async fn spend_status(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, manifest) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let budget = apiary_runtime::spend::tokens_per_day(&manifest.governance.budgets)
        .ok()
        .flatten();
    let day = apiary_runtime::spend::SpendLedger::open(&dir).today();
    match day {
        Ok(d) => {
            let used = d.input_tokens + d.output_tokens;
            let reserved: u64 = d.reservations.iter().map(|r| r.amount).sum();
            Json(json!({
                "ok": true,
                "npub": npub,
                "date": d.date,
                "input_tokens": d.input_tokens,
                "output_tokens": d.output_tokens,
                "used": used,
                "reserved": reserved,
                "budget_tokens_per_day": budget,
                "remaining": budget.map(|b| b.saturating_sub(used + reserved)),
            }))
            .into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

// ---------------------------------------------------------------- log pub

pub async fn log_publish(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (ks, npub, dir, _raw, manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&[]), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let relays = manifest.memory.log_relays.clone();
    if relays.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "manifest has no memory.log_relays — add relay URLs to the manifest first",
        )
        .into_response();
    }
    let out = tokio::task::spawn_blocking(move || {
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        apiary_runtime::publish::publish_log(&dir, &custody, &handle, &relays)
            .map(|report| (npub, report))
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok((npub, r)) => Json(json!({
            "ok": true,
            "npub": npub,
            "published_public": r.published_public,
            "published_wrapped": r.published_wrapped,
            "skipped_local": r.skipped_local,
            "already_published": r.already_published,
            "relays": r.relay_results,
        }))
        .into_response(),
        Err(e) => e.into_response(),
    }
}

pub async fn log_remote(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, manifest) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let relays = manifest.memory.log_relays.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, Resp> {
        let pk = apiary_core::identity::parse_npub(&npub)
            .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        let mut summary = Vec::new();
        for relay in &relays {
            let own = json!({
                "authors": [pk.to_hex()],
                "kinds": [apiary_core::log::LOG_ENTRY_KIND, apiary_runtime::publish::WRAPPED_KIND],
            });
            let about = json!({
                "kinds": [apiary_core::log::LOG_ENTRY_KIND],
                "#p": [pk.to_hex()],
            });
            let fetched = apiary_runtime::relay::fetch(relay, own).and_then(|mut a| {
                let b = apiary_runtime::relay::fetch(relay, about)?;
                for e in b {
                    if !a.iter().any(|x| x.id == e.id) {
                        a.push(e);
                    }
                }
                Ok(a)
            });
            match fetched {
                Ok(events) => {
                    let mut items = Vec::new();
                    for e in &events {
                        if e.verify().is_err() {
                            continue;
                        }
                        let wrapped = e.kind.as_u16() == apiary_runtime::publish::WRAPPED_KIND;
                        // unwrap_self_entry yields the INNER signed log
                        // event; its content is the entry body.
                        let body: Option<serde_json::Value> = if wrapped {
                            apiary_runtime::publish::unwrap_self_entry(&custody, &handle, e)
                                .ok()
                                .and_then(|inner| serde_json::from_str(&inner.content).ok())
                        } else {
                            serde_json::from_str(&e.content).ok()
                        };
                        items.push(json!({
                            "id": e.id.to_hex(),
                            "at": e.created_at.as_secs(),
                            "signer": e.pubkey.to_hex(),
                            "kind": e.kind.as_u16(),
                            "wrapped": wrapped,
                            "body": body,
                        }));
                    }
                    summary.push(json!({"relay": relay, "ok": true, "events": items}));
                }
                Err(e) => {
                    summary.push(json!({"relay": relay, "ok": false, "error": e.to_string()}))
                }
            }
        }
        Ok(json!({"ok": true, "npub": npub, "relays": summary}))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------- ratify io

#[derive(serde::Deserialize)]
pub struct RatifyExportBody {
    /// The external human's key (npub or hex) that will sign elsewhere.
    r#as: String,
}

/// Emit the UNSIGNED ratification event so a human can sign with their own
/// nostr tooling — their master key never enters Apiary.
pub async fn ratify_export(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, _dir, raw, manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: RatifyExportBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let ratifier = match apiary_core::identity::parse_npub(&body.r#as) {
        Ok(pk) => pk,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if !suspend_pks(&manifest).contains(&ratifier) {
        return err(
            StatusCode::FORBIDDEN,
            "that key is not in this agent's governance.suspend_keys — only a named human can ratify",
        )
        .into_response();
    }
    match ceremony::ratification_unsigned(ratifier, &npub, &raw) {
        Ok(unsigned) => Json(json!({
            "ok": true,
            "npub": npub,
            "sign_as": body.r#as,
            "unsigned_event": serde_json::from_str::<serde_json::Value>(&unsigned.as_json())
                .unwrap_or_default(),
            "note": "sign this with your own nostr tooling, then import the signed event",
        }))
        .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct RatifyImportBody {
    event: serde_json::Value,
}

pub async fn ratify_import(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, dir, raw, manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: RatifyImportBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let event = match Event::from_json(body.event.to_string()) {
        Ok(e) => e,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                format!("could not parse event: {e}"),
            )
            .into_response()
        }
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let listed = suspend_pks(&manifest);
    let out = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, Resp> {
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        let log = EpisodicLog::open(&dir);
        // A complete founding needs BOTH signatures: the agent signs its
        // manifest here, then the external human event is verified in.
        let signed = ceremony::sign_manifest(&custody, &handle, &log, &raw)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        ceremony::import_ratification(&log, &event, &raw, &listed)
            .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
        Ok(json!({
            "ok": true,
            "npub": npub,
            "agent_signed": signed.id.to_hex(),
            "imported": event.id.to_hex(),
            "ratified_by": event.pubkey.to_hex(),
            "manifest_sha256": ceremony::manifest_hash(&raw),
        }))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------- creds

#[derive(serde::Deserialize)]
pub struct SealBody {
    plaintext: String,
}

pub async fn credential_seal(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: SealBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let out = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, Resp> {
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        let blob = custody
            .seal(&handle, body.plaintext.trim_end())
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        Ok(json!({"ok": true, "npub": npub, "nip44": blob.nip44}))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct OpenBody {
    nip44: String,
}

/// Dev/debug only — returns plaintext to the caller. The cockpit warns
/// before calling this.
pub async fn credential_open(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: OpenBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let out = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, Resp> {
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        let blob = apiary_core::manifest::EncryptedBlob {
            nip44: body.nip44.trim().to_string(),
        };
        let plaintext = custody
            .open(&handle, &blob)
            .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
        Ok(json!({"ok": true, "npub": npub, "plaintext": plaintext.as_str()}))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------- buzz

#[derive(serde::Deserialize)]
pub struct RelayQuery {
    relay: String,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    30
}

/// Open an authenticated Buzz session for one operation.
fn buzz_session_op<T: Send + 'static>(
    ks: Keystore,
    npub: String,
    pass: String,
    relay: String,
    f: impl FnOnce(
            &mut apiary_runtime::buzz::BuzzSession,
            &Custody,
            &apiary_core::custody::AgentHandle,
            &std::path::Path,
        ) -> Result<T, crate::ops::Resp>
        + Send
        + 'static,
) -> tokio::task::JoinHandle<Result<T, Resp>> {
    tokio::task::spawn_blocking(move || {
        let dir = ks.agent_dir(&npub);
        let (custody, handle) = admit(&ks, &npub, &pass)?;
        let mut session = apiary_runtime::buzz::BuzzSession::connect(&relay, &custody, &handle)
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
        f(&mut session, &custody, &handle, &dir)
    })
}

pub async fn buzz_channels(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    Query(q): Query<RelayQuery>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _m) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let relay = q.relay.clone();
    let out = buzz_session_op(ks, npub, pass, relay.clone(), move |session, _c, _h, _d| {
        let channels: Vec<serde_json::Value> = session
            .channels()
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?
            .iter()
            .filter_map(|e| {
                let mut id = None;
                let mut name = None;
                for t in e.tags.iter() {
                    let s = t.as_slice();
                    match s.first().map(String::as_str) {
                        Some("d") => id = s.get(1).cloned(),
                        Some("name") => name = s.get(1).cloned(),
                        _ => {}
                    }
                }
                Some(json!({"id": id?, "name": name}))
            })
            .collect();
        Ok(json!({"ok": true, "relay": relay, "channels": channels}))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

pub async fn buzz_read(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    Query(q): Query<RelayQuery>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _m) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let Some(channel) = q.channel.clone() else {
        return err(StatusCode::BAD_REQUEST, "channel is required").into_response();
    };
    let limit = q.limit;
    let out = buzz_session_op(
        ks,
        npub,
        pass,
        q.relay.clone(),
        move |session, _c, _h, _d| {
            let msgs: Vec<serde_json::Value> = session
                .read_channel(&channel, limit)
                .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id.to_hex(),
                        "at": e.created_at.as_secs(),
                        "author": e.pubkey.to_hex(),
                        "content": e.content,
                    })
                })
                .collect();
            Ok(json!({"ok": true, "channel": channel, "messages": msgs}))
        },
    )
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct BuzzPostBody {
    relay: String,
    channel: String,
    message: String,
}

pub async fn buzz_post(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _m) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: BuzzPostBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let relay = body.relay.clone();
    let out = buzz_session_op(ks, npub, pass, relay.clone(), move |session, c, h, dir| {
        let event = session
            .post(&body.channel, &body.message, &[])
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
        // Membership acts are part of the record — same entry the CLI writes.
        EpisodicLog::open(dir)
            .append(
                c,
                h,
                apiary_core::log::Tier::Self_,
                &apiary_core::log::EntryBody {
                    action: "buzz.post".into(),
                    model: None,
                    cost: None,
                    harness: None,
                    outcome: "ok".into(),
                    detail: Some(json!({
                        "relay": relay,
                        "channel": body.channel,
                        "event": event.id.to_hex(),
                        "chars": body.message.len(),
                    })),
                },
            )
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        Ok(json!({
            "ok": true,
            "channel": body.channel,
            "event": event.id.to_hex(),
        }))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct BuzzProfileBody {
    relay: String,
    name: String,
    #[serde(default)]
    about: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

pub async fn buzz_profile(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _m) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: BuzzProfileBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let relay = body.relay.clone();
    let out = buzz_session_op(ks, npub, pass, relay.clone(), move |session, c, h, dir| {
        let event = session
            .set_profile(&body.name, body.about.as_deref(), body.picture.as_deref())
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
        EpisodicLog::open(dir)
            .append(
                c,
                h,
                apiary_core::log::Tier::Public,
                &apiary_core::log::EntryBody {
                    action: "buzz.profile".into(),
                    model: None,
                    cost: None,
                    harness: None,
                    outcome: "ok".into(),
                    detail: Some(json!({
                        "relay": relay,
                        "name": body.name,
                        "event": event.id.to_hex(),
                    })),
                },
            )
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        Ok(json!({"ok": true, "name": body.name, "event": event.id.to_hex()}))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct BuzzJoinBody {
    relay: String,
    channel: String,
}

pub async fn buzz_join(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, _dir, _raw, _m) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: BuzzJoinBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let pass = match require_pass(&state) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let out = buzz_session_op(ks, npub, pass, body.relay.clone(), move |session, _c, _h, _d| {
        let event = session
            .join_channel(&body.channel)
            .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
        Ok(json!({
            "ok": true,
            "channel": body.channel,
            "event": event.id.to_hex(),
            "note": "join requested — open channels admit immediately, private ones await an admin",
        }))
    })
    .await
    .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------- listener

#[derive(serde::Deserialize)]
pub struct ListenBody {
    relay: String,
    #[serde(default)]
    trigger: Option<String>,
}

/// Start a listener for an agent unless one is already running. The manual
/// endpoint and the supervisor share this path, so the gates are identical:
/// ratified constitution, unlocked keystore, one listener per agent.
pub async fn ensure_listener(
    state: &App,
    npub: &str,
    relay: &str,
    trigger: Option<String>,
) -> Result<serde_json::Value, Resp> {
    let ks = Keystore::open(&state.home).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let dir = ks.agent_dir(npub);
    let raw = std::fs::read_to_string(dir.join("manifest.yaml"))
        .map_err(|e| err(StatusCode::NOT_FOUND, e))?;
    let manifest = apiary_core::manifest::Manifest::from_yaml(&raw)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let pass = require_pass(state)?;
    // One listener per agent; reap a finished one silently.
    {
        let mut map = state.listeners.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.get(npub) {
            if !existing.done.load(Ordering::Relaxed) {
                return Err(err(
                    StatusCode::CONFLICT,
                    "listener already running for this agent",
                ));
            }
            map.remove(npub);
        }
    }
    // Nothing runs unratified — same gate as the CLI.
    let agent_pk =
        apiary_core::identity::parse_npub(npub).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    let log = EpisodicLog::open(&dir);
    match ceremony::is_ratified(&log, &raw, &agent_pk, &suspend_pks(&manifest)) {
        Ok(true) => {}
        Ok(false) => {
            return Err(err(
                StatusCode::PRECONDITION_FAILED,
                "manifest is not ratified — nothing runs unratified",
            ))
        }
        Err(e) => return Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
    let name = std::fs::read_to_string(dir.join("name"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let trigger = trigger
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| format!("@{name}"));
    // Load keys off the async runtime (NIP-49 scrypt is slow by design),
    // so a wrong passphrase fails HERE, not silently inside the thread.
    let npub2 = npub.to_string();
    let ks2 = Keystore::open(&state.home).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let admit_result = tokio::task::spawn_blocking(move || admit(&ks2, &npub2, &pass)).await;
    let (custody, handle) = match admit_result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let lines = Arc::new(Mutex::new(VecDeque::new()));
    let entry = ListenerHandle {
        stop: stop.clone(),
        done: done.clone(),
        relay: relay.to_string(),
        trigger: trigger.clone(),
        started_at: now_secs(),
        lines: lines.clone(),
        manifest_sha: ceremony::manifest_hash(&raw),
    };
    let relay2 = relay.to_string();
    let trigger2 = trigger.clone();
    std::thread::spawn(move || {
        push_line(&lines, format!("listening (trigger {trigger2:?} or p-tag)"));
        let sink_lines = lines.clone();
        let result = apiary_runtime::buzz::run_mention_service(
            &manifest,
            &dir,
            &custody,
            &handle,
            &relay2,
            &trigger2,
            &stop,
            move |line| push_line(&sink_lines, line),
        );
        match result {
            Ok(()) => push_line(&lines, "listener stopped".into()),
            Err(e) => push_line(&lines, format!("listener died: {e}")),
        }
        done.store(true, Ordering::Relaxed);
    });
    state
        .listeners
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(npub.to_string(), entry);
    Ok(json!({
        "ok": true,
        "npub": npub,
        "relay": relay,
        "trigger": trigger,
        "running": true,
    }))
}

/// Start the managed mention listener for an agent: ratification-gated,
/// runs run_mention_service on a detached thread, activity into a ring
/// buffer the status endpoint serves.
pub async fn listener_start(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, _dir, _raw, _manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: ListenBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    match ensure_listener(&state, &npub, &body.relay, body.trigger).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

pub async fn listener_status(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, m) = match gate(&state, &headers, "GET", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let active = is_active(&dir);
    let declared = m.presence.buzz.as_ref().map(|b| b.relay.clone());
    let map = state.listeners.lock().unwrap_or_else(|e| e.into_inner());
    match map.get(&npub) {
        Some(l) => {
            let lines: Vec<String> = l
                .lines
                .lock()
                .map(|q| q.iter().rev().take(60).rev().cloned().collect())
                .unwrap_or_default();
            Json(json!({
                "ok": true,
                "npub": npub,
                "running": !l.done.load(Ordering::Relaxed),
                "relay": l.relay,
                "trigger": l.trigger,
                "started_at": l.started_at,
                "lines": lines,
                "active": active,
                "declared_relay": declared,
            }))
            .into_response()
        }
        None => Json(json!({
            "ok": true,
            "npub": npub,
            "running": false,
            "active": active,
            "declared_relay": declared,
        }))
        .into_response(),
    }
}

pub async fn listener_stop(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, _dir, _raw, _m) = match gate(&state, &headers, "DELETE", &uri, None, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let mut map = state.listeners.lock().unwrap_or_else(|e| e.into_inner());
    match map.remove(&npub) {
        Some(l) => {
            l.stop.store(true, Ordering::Relaxed);
            Json(json!({
                "ok": true,
                "npub": npub,
                "running": false,
                "note": "stop signalled — the thread exits within its keepalive interval (≤15s)",
            }))
            .into_response()
        }
        None => err(StatusCode::NOT_FOUND, "no listener for this agent").into_response(),
    }
}

// ---------------------------------------------------------------- activation

/// Host-local operational state: while a marker file exists in the agent's
/// directory, this host considers the agent ACTIVE and supervises its
/// declared standing presence. Deliberately NOT in the manifest — which
/// workspace the agent lives in is constitutional (presence.buzz, ratified);
/// whether this host is currently running it is an operator switch.
pub fn is_active(dir: &std::path::Path) -> bool {
    dir.join("active").exists()
}

#[derive(serde::Deserialize)]
pub struct ActiveBody {
    active: bool,
}

pub async fn set_active(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: ActiveBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let marker = dir.join("active");
    let result = if body.active {
        std::fs::write(&marker, b"1")
    } else {
        match std::fs::remove_file(&marker) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    };
    if let Err(e) = result {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    // Deactivation takes effect immediately rather than on the next
    // supervisor tick.
    if !body.active {
        let mut map = state.listeners.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(l) = map.remove(&npub) {
            l.stop.store(true, Ordering::Relaxed);
        }
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "active": body.active,
        "buzz_declared": manifest.presence.buzz.is_some(),
        "note": if body.active {
            "active — the supervisor starts declared presence within ~10s"
        } else {
            "inactive — standing presence stopped; one-shot runs stay available"
        },
    }))
    .into_response()
}

// ---------------------------------------------------------------- supervisor

/// The presence supervisor: reconciles desired state (agent ACTIVE and
/// manifest declares presence.buzz) with reality (listener running) every
/// tick. Starts declared listeners, restarts dead ones (with backoff so a
/// dead relay is not hammered), and stops any listener whose agent went
/// inactive. Locked keystore and unratified manifests simply wait — the
/// supervisor never weakens a gate, it only presses the same button an
/// operator would.
pub fn spawn_supervisor(state: App) {
    tokio::spawn(async move {
        let mut last_attempt: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            reconcile(&state, &mut last_attempt).await;
        }
    });
}

const RETRY_BACKOFF_SECS: u64 = 30;

async fn reconcile(state: &App, last_attempt: &mut std::collections::HashMap<String, u64>) {
    let Ok(ks) = Keystore::open(&state.home) else {
        return;
    };
    let Ok(agents) = ks.list() else {
        return;
    };
    for npub in agents {
        let dir = ks.agent_dir(&npub);
        let active = is_active(&dir);
        let disk_sha = std::fs::read_to_string(dir.join("manifest.yaml"))
            .ok()
            .map(|raw| ceremony::manifest_hash(&raw));
        let running = {
            let mut map = state.listeners.lock().unwrap_or_else(|e| e.into_inner());
            match map.get(&npub) {
                Some(l) if !l.done.load(Ordering::Relaxed) => {
                    if !active {
                        // Inactive agents hold no standing presence, however
                        // the listener was started.
                        if let Some(l) = map.remove(&npub) {
                            l.stop.store(true, Ordering::Relaxed);
                        }
                        continue;
                    } else if disk_sha.as_deref() != Some(l.manifest_sha.as_str()) {
                        // Constitution changed under a live listener: stop it.
                        // ensure_listener refuses to restart until the new
                        // manifest is ratified, then brings it back with the
                        // new capabilities bound.
                        eprintln!(
                            "supervisor: manifest changed for {npub} — stopping listener pending re-ratification"
                        );
                        if let Some(l) = map.remove(&npub) {
                            l.stop.store(true, Ordering::Relaxed);
                        }
                        continue;
                    } else {
                        true
                    }
                }
                Some(_) => {
                    // Finished thread: reap so a restart can happen below.
                    map.remove(&npub);
                    false
                }
                None => false,
            }
        };
        if !active || running {
            continue;
        }
        let declared = std::fs::read_to_string(dir.join("manifest.yaml"))
            .ok()
            .and_then(|raw| apiary_core::manifest::Manifest::from_yaml(&raw).ok())
            .and_then(|m| m.presence.buzz);
        let Some(buzz) = declared else {
            continue; // active, but no declared presence — nothing to supervise
        };
        if state.passphrase_clone().is_none() {
            continue; // locked keystore: wait for the operator to unlock
        }
        let now = now_secs();
        if now.saturating_sub(*last_attempt.get(&npub).unwrap_or(&0)) < RETRY_BACKOFF_SECS {
            continue;
        }
        last_attempt.insert(npub.clone(), now);
        match ensure_listener(state, &npub, &buzz.relay, buzz.trigger.clone()).await {
            Ok(_) => eprintln!("supervisor: started listener for {npub} on {}", buzz.relay),
            Err((_, body)) => eprintln!(
                "supervisor: could not start listener for {npub}: {}",
                body.0
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("unknown")
            ),
        }
    }
}

// ---------------------------------------------------------------- connectors

/// The host connector library: named, reusable connector CONFIGURATIONS
/// (kind + caps), stored host-side in connectors.yaml. Deliberately no
/// secrets — a credential is sealed per-agent at grant time, because NIP-44
/// blobs bind to one key and a library secret would be a shared secret.
///
/// Granting copies a library entry into an agent's manifest connectors[]
/// (sealing a credential to that agent if provided). That edit changes the
/// manifest hash, so every grant is ratified by a human — and because the
/// grant lives in the manifest, it travels with the agent: portability
/// includes capabilities and their sealed credentials. The destination
/// host must merely bind the kind (BOUND_KINDS); an unbindable declared
/// connector fails loudly at run start.
#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct ConnectorLibrary {
    #[serde(default)]
    pub connectors: Vec<LibraryEntry>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct LibraryEntry {
    /// Human label, unique in the library ("publish-main").
    pub name: String,
    /// Connector kind the host binds ("nostr-publish").
    pub kind: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub caps: std::collections::BTreeMap<String, serde_json::Value>,
}

fn library_path(state: &AppState) -> std::path::PathBuf {
    state.home.join("connectors.yaml")
}

fn load_library(state: &AppState) -> Result<ConnectorLibrary, Resp> {
    let p = library_path(state);
    if !p.exists() {
        return Ok(ConnectorLibrary::default());
    }
    let raw = std::fs::read_to_string(&p).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    serde_yaml::from_str(&raw).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("connectors.yaml: {e}"),
        )
    })
}

pub async fn connectors_get(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    if let Err(e) = nip98::check(&state, &headers, "GET", &pq, None) {
        return e.into_response();
    }
    match load_library(&state) {
        Ok(lib) => Json(json!({
            "ok": true,
            "library": lib.connectors,
            "host_binds": apiary_runtime::connector::BOUND_KINDS,
        }))
        .into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct LibraryBody {
    library: Vec<LibraryEntry>,
}

pub async fn connectors_put(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    if let Err(e) = nip98::check(&state, &headers, "PUT", &pq, Some(&raw_body)) {
        return e.into_response();
    }
    let body: LibraryBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let mut seen = std::collections::HashSet::new();
    for e2 in &body.library {
        if e2.name.trim().is_empty() {
            return err(StatusCode::BAD_REQUEST, "library entry with empty name").into_response();
        }
        if !seen.insert(e2.name.clone()) {
            return err(
                StatusCode::BAD_REQUEST,
                format!("duplicate library name '{}'", e2.name),
            )
            .into_response();
        }
        if !apiary_runtime::connector::BOUND_KINDS.contains(&e2.kind.as_str()) {
            return err(
                StatusCode::BAD_REQUEST,
                format!(
                    "kind '{}' is not bindable by this host (host binds: {})",
                    e2.kind,
                    apiary_runtime::connector::BOUND_KINDS.join(", ")
                ),
            )
            .into_response();
        }
    }
    let lib = ConnectorLibrary {
        connectors: body.library,
    };
    let yaml = match serde_yaml::to_string(&lib) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(e) = std::fs::write(library_path(&state), yaml) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    Json(json!({"ok": true, "count": lib.connectors.len()})).into_response()
}

#[derive(serde::Deserialize)]
pub struct GrantBody {
    /// Library entry name to grant.
    name: String,
    /// Optional secret to seal to THIS agent (API key etc.). Never stored
    /// anywhere else — the sealed blob lands in the manifest.
    #[serde(default)]
    credential: Option<String>,
}

pub async fn connector_grant(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let (ks, npub, dir, raw, mut manifest) =
        match gate(&state, &headers, "POST", &uri, Some(&raw_body), &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let body: GrantBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let lib = match load_library(&state) {
        Ok(l) => l,
        Err(e) => return e.into_response(),
    };
    let Some(entry) = lib.connectors.iter().find(|c| c.name == body.name) else {
        return err(
            StatusCode::NOT_FOUND,
            format!("no library entry named '{}'", body.name),
        )
        .into_response();
    };
    // Seal the credential to THIS agent, if one was provided.
    let credential = match body.credential.as_deref().filter(|c| !c.is_empty()) {
        None => None,
        Some(secret) => {
            let pass = match require_pass(&state) {
                Ok(p) => p,
                Err(e) => return e.into_response(),
            };
            let npub2 = npub.clone();
            let secret = secret.to_string();
            let sealed = tokio::task::spawn_blocking(move || {
                let (custody, handle) = admit(&ks, &npub2, &pass)?;
                custody
                    .seal(&handle, secret.trim_end())
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))
            })
            .await
            .unwrap_or_else(|e| Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)));
            match sealed {
                Ok(blob) => Some(blob),
                Err(e) => return e.into_response(),
            }
        }
    };
    // Upsert by kind: one manifest entry per connector kind.
    manifest.connectors.retain(|c| c.kind != entry.kind);
    manifest.connectors.push(apiary_core::manifest::Connector {
        kind: entry.kind.clone(),
        credential,
        caps: entry.caps.clone(),
    });
    let yaml = match serde_yaml::to_string(&manifest) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(e) = std::fs::write(dir.join("manifest.yaml"), &yaml) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    let _ = raw; // superseded
    Json(json!({
        "ok": true,
        "npub": npub,
        "granted": entry.name,
        "kind": entry.kind,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "grant written to the manifest — a capability change is an amendment; re-ratify before the agent runs again",
    }))
    .into_response()
}

pub async fn connector_revoke(
    State(state): State<App>,
    AxPath((npub, kind)): AxPath<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (_ks, npub, dir, _raw, mut manifest) =
        match gate(&state, &headers, "DELETE", &uri, None, &npub) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
    let before = manifest.connectors.len();
    manifest.connectors.retain(|c| c.kind != kind);
    if manifest.connectors.len() == before {
        return err(
            StatusCode::NOT_FOUND,
            format!("agent has no '{kind}' connector"),
        )
        .into_response();
    }
    let yaml = match serde_yaml::to_string(&manifest) {
        Ok(y) => y,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    if let Err(e) = std::fs::write(dir.join("manifest.yaml"), &yaml) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    Json(json!({
        "ok": true,
        "npub": npub,
        "revoked": kind,
        "manifest_sha256": ceremony::manifest_hash(&yaml),
        "ratified": false,
        "note": "revocation is an amendment too — re-ratify. Until then the agent cannot run at all.",
    }))
    .into_response()
}
