//! NIP-98 HTTP auth — the nostr×AG-UI seam (SPEC §10): a signed ephemeral
//! event in the Authorization header binds the request to an npub.
//!
//! Spec-exact per NIP-98: the `u` tag must match the request's absolute URL
//! EXACTLY (query included), the `method` tag must match, and body-bearing
//! requests must carry a `payload` tag with the SHA-256 of the body — so a
//! captured header authorizes nothing beyond the one request it signed.
//!
//! Authentication is not authorization: `check` yields the signer, and the
//! caller must bind it to the operation (governorship) — see `authorize`.

use crate::{AppState, AuthMode};
use apiary_core::manifest::{ManagerRole, Manifest};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use nostr::prelude::*;
use sha2::{Digest, Sha256};

const NIP98_KIND: u16 = 27235;
const CONTROL_TOKEN_KIND: u16 = 27236;
const FRESHNESS_SECS: u64 = 60;
const MAX_CONTROL_TOKEN_SECS: u64 = 90 * 24 * 60 * 60;
const CONTROL_TOKEN_REGISTRY: &str = "control-tokens.json";

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ControlTokenFile {
    version: u32,
    tokens: Vec<ControlTokenRecord>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlTokenRecord {
    pub id: String,
    pub agent: String,
    pub label: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

fn load_control_tokens(state: &AppState) -> Result<ControlTokenFile, String> {
    let path = state.home.join(CONTROL_TOKEN_REGISTRY);
    match std::fs::read_to_string(&path) {
        Ok(raw) => {
            let file: ControlTokenFile = serde_json::from_str(&raw)
                .map_err(|error| format!("{} is invalid: {error}", path.display()))?;
            if file.version != 1 {
                return Err(format!(
                    "{} has unsupported version {}",
                    path.display(),
                    file.version
                ));
            }
            Ok(file)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ControlTokenFile {
            version: 1,
            tokens: Vec::new(),
        }),
        Err(error) => Err(format!("could not read {}: {error}", path.display())),
    }
}

fn save_control_tokens(state: &AppState, file: &ControlTokenFile) -> Result<(), String> {
    std::fs::create_dir_all(&state.home).map_err(|error| error.to_string())?;
    let path = state.home.join(CONTROL_TOKEN_REGISTRY);
    let temporary = state.home.join("control-tokens.json.tmp");
    let body = serde_json::to_vec_pretty(file).map_err(|error| error.to_string())?;
    std::fs::write(&temporary, body).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    std::fs::rename(&temporary, &path).map_err(|error| error.to_string())
}

pub fn register_control_token(state: &AppState, record: ControlTokenRecord) -> Result<(), String> {
    let _guard = state
        .control_tokens
        .lock()
        .map_err(|_| "control-token registry is unavailable".to_string())?;
    let mut file = load_control_tokens(state)?;
    if file.tokens.iter().any(|token| token.id == record.id) {
        return Err("control-token ID collision".into());
    }
    file.tokens.push(record);
    save_control_tokens(state, &file)
}

pub fn list_control_tokens(
    state: &AppState,
    agent: &str,
) -> Result<Vec<ControlTokenRecord>, String> {
    let _guard = state
        .control_tokens
        .lock()
        .map_err(|_| "control-token registry is unavailable".to_string())?;
    let mut tokens = load_control_tokens(state)?
        .tokens
        .into_iter()
        .filter(|token| token.agent == agent)
        .collect::<Vec<_>>();
    tokens.sort_by_key(|token| std::cmp::Reverse(token.created_at));
    Ok(tokens)
}

pub fn list_all_control_tokens(state: &AppState) -> Result<Vec<ControlTokenRecord>, String> {
    let _guard = state
        .control_tokens
        .lock()
        .map_err(|_| "control-token registry is unavailable".to_string())?;
    let mut tokens = load_control_tokens(state)?.tokens;
    tokens.sort_by_key(|token| std::cmp::Reverse(token.created_at));
    Ok(tokens)
}

pub fn revoke_control_token(
    state: &AppState,
    agent: &str,
    id: &str,
) -> Result<ControlTokenRecord, String> {
    let _guard = state
        .control_tokens
        .lock()
        .map_err(|_| "control-token registry is unavailable".to_string())?;
    let mut file = load_control_tokens(state)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let token = file
        .tokens
        .iter_mut()
        .find(|token| token.agent == agent && token.id == id)
        .ok_or_else(|| "control token not found for this agent".to_string())?;
    token.revoked_at.get_or_insert(now);
    let result = token.clone();
    save_control_tokens(state, &file)?;
    Ok(result)
}

fn constant_time_eq(presented: &str, expected: &str) -> bool {
    presented.len() == expected.len()
        && presented
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Authenticate the MCP control endpoint. In addition to ordinary NIP-98,
/// it accepts a time-bounded token signed by an Apiary agent's own Nostr key.
/// The bearer proves only identity; every called REST operation still checks
/// that identity against the target agent or host-manager allowlist.
pub fn check_control(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    body: Option<&[u8]>,
) -> Result<Option<PublicKey>, (StatusCode, Json<serde_json::Value>)> {
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer apiary_"));
    if let Some(encoded) = bearer {
        return verify_control_token(state, encoded).map(Some);
    }
    check(state, headers, method, path_and_query, body)
}

pub fn issue_control_token(
    custody: &apiary_core::custody::Custody,
    handle: &apiary_core::custody::AgentHandle,
    host_id: &str,
    expires_in_secs: u64,
) -> Result<(String, ControlTokenRecord), apiary_core::Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ttl = expires_in_secs.clamp(60, MAX_CONTROL_TOKEN_SECS);
    let expires_at = now.saturating_add(ttl);
    let audience = format!("apiary-host:{host_id}");
    let event = custody.sign(
        handle,
        EventBuilder::new(Kind::Custom(CONTROL_TOKEN_KIND), "apiary-control")
            .tag(Tag::custom("aud", vec![audience]))
            .tag(Tag::custom("exp", vec![expires_at.to_string()])),
    )?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(event.as_json());
    let agent = apiary_core::identity::to_npub(&event.pubkey)?;
    Ok((
        format!("apiary_{encoded}"),
        ControlTokenRecord {
            id: event.id.to_hex(),
            agent,
            label: String::new(),
            created_at: event.created_at.as_secs(),
            expires_at,
            revoked_at: None,
        },
    ))
}

fn verify_control_token(
    state: &AppState,
    encoded: &str,
) -> Result<PublicKey, (StatusCode, Json<serde_json::Value>)> {
    let fail = |message: &str| {
        crate::err(
            StatusCode::UNAUTHORIZED,
            format!("apiary control token: {message}"),
        )
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| fail("bad base64"))?;
    let event = Event::from_json(String::from_utf8_lossy(&bytes).as_ref())
        .map_err(|_| fail("bad event JSON"))?;
    if event.kind != Kind::Custom(CONTROL_TOKEN_KIND) || event.content != "apiary-control" {
        return Err(fail("wrong kind or purpose"));
    }
    event.verify().map_err(|_| fail("bad signature"))?;
    let tag = |name: &str| {
        event.tags.iter().find_map(|tag| {
            let values = tag.as_slice();
            (values.first().map(String::as_str) == Some(name)).then(|| values.get(1).cloned())?
        })
    };
    let audience = format!(
        "apiary-host:{}",
        apiary_runtime::lease::host_id(&state.home)
    );
    if tag("aud").as_deref() != Some(audience.as_str()) {
        return Err(fail("audience does not match this Apiary host"));
    }
    let expires_at = tag("exp")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| fail("missing or invalid expiry"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if expires_at <= now {
        return Err(fail("expired"));
    }
    if event.created_at.as_secs() > now.saturating_add(FRESHNESS_SECS)
        || expires_at.saturating_sub(event.created_at.as_secs()) > MAX_CONTROL_TOKEN_SECS
    {
        return Err(fail("lifetime is invalid"));
    }
    let id = event.id.to_hex();
    let agent = apiary_core::identity::to_npub(&event.pubkey)
        .map_err(|_| fail("agent identity is invalid"))?;
    let _guard = state
        .control_tokens
        .lock()
        .map_err(|_| fail("registry is unavailable"))?;
    let file = load_control_tokens(state).map_err(|_| fail("registry is unavailable"))?;
    let registered = file
        .tokens
        .iter()
        .find(|token| token.id == id && token.agent == agent && token.expires_at == expires_at)
        .ok_or_else(|| fail("not registered or invalidated by an upgrade"))?;
    if registered.revoked_at.is_some() {
        return Err(fail("revoked"));
    }
    Ok(event.pubkey)
}

/// Authenticate a request. `path_and_query` is the exact request target
/// (e.g. "/api/agents/npub1…/log?tail=50"); `body` is the raw body for
/// mutating requests (None for bodyless GETs).
pub fn check(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    body: Option<&[u8]>,
) -> Result<Option<PublicKey>, (StatusCode, Json<serde_json::Value>)> {
    // Only the in-process MCP adapter knows this random capability. It may
    // forward the already-authenticated signer into the ordinary REST gates;
    // untrusted callers cannot manufacture this header pair.
    let internal = headers
        .get("x-apiary-internal-token")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| constant_time_eq(value, &state.internal_token));
    if internal {
        return headers
            .get("x-apiary-internal-signer")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(apiary_core::identity::parse_npub)
            .transpose()
            .map_err(|error| crate::err(StatusCode::UNAUTHORIZED, error));
    }
    // Desktop token gate: when the host carries a per-launch token, every
    // request must present it (header or, for the boot navigation and SSE,
    // query param). This binds the embedded daemon to its own webview —
    // other local processes never saw the token. Orthogonal to auth mode.
    if let Some(expected) = state.token.as_deref() {
        let from_header = headers
            .get("x-apiary-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let from_query = path_and_query.split_once('?').and_then(|(_, q)| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix("token=").map(str::to_string))
        });
        let presented = from_header.or(from_query).unwrap_or_default();
        // Constant-time-ish compare; the token is 32 random bytes of hex.
        let ok = constant_time_eq(&presented, expected);
        if !ok {
            return Err(crate::err(
                StatusCode::UNAUTHORIZED,
                "missing or wrong host token",
            ));
        }
    }
    if state.auth == AuthMode::Open {
        return Ok(None);
    }
    let fail = |msg: &str| crate::err(StatusCode::UNAUTHORIZED, format!("nip98: {msg}"));

    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| fail("missing Authorization header"))?;
    let b64 = header
        .strip_prefix("Nostr ")
        .ok_or_else(|| fail("expected 'Authorization: Nostr <base64 event>'"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| fail("bad base64"))?;
    let event = Event::from_json(String::from_utf8_lossy(&bytes).as_ref())
        .map_err(|_| fail("bad event JSON"))?;

    if event.kind != Kind::Custom(NIP98_KIND) {
        return Err(fail("wrong kind (want 27235)"));
    }
    event.verify().map_err(|_| fail("bad signature"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(event.created_at.as_secs()) > FRESHNESS_SECS {
        return Err(fail("stale event (replay window exceeded)"));
    }

    let tag = |name: &str| {
        event.tags.iter().find_map(|t| {
            let s = t.as_slice();
            (s.first().map(String::as_str) == Some(name)).then(|| s.get(1).cloned())?
        })
    };

    // Exact absolute-URL match against the daemon's canonical origin.
    let expected = format!("{}{}", state.origin, path_and_query);
    if tag("u").as_deref() != Some(expected.as_str()) {
        return Err(fail(&format!("u tag must be exactly {expected}")));
    }
    if tag("method").as_deref() != Some(method) {
        return Err(fail("method tag mismatch"));
    }
    // Body binding: mutating requests must hash their payload.
    if let Some(body) = body {
        let want = format!("{:x}", Sha256::digest(body));
        if tag("payload").as_deref() != Some(want.as_str()) {
            return Err(fail("payload tag missing or does not match body sha256"));
        }
    }
    Ok(Some(event.pubkey))
}

/// Bind authentication to authorization: in nip98 mode the signer must be a
/// GOVERNOR of the agent (a listed suspend key). In open mode (localhost
/// dev trust, loudly warned at startup) there is no signer to bind.
pub fn authorize_governor(
    state: &AppState,
    signer: Option<PublicKey>,
    suspend_keys: &[PublicKey],
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // A signer-less request in open mode is the trusted local desktop
    // operator. An explicit signer (notably a signed MCP control token)
    // always acts as that identity and must never inherit operator access.
    if state.auth == AuthMode::Open && signer.is_none() {
        return Ok(());
    }
    match signer {
        Some(pk) if suspend_keys.contains(&pk) => Ok(()),
        Some(_) => Err(crate::err(
            StatusCode::FORBIDDEN,
            "signer is not a governor (suspend key) of this agent",
        )),
        None => Err(crate::err(
            StatusCode::UNAUTHORIZED,
            "authentication required",
        )),
    }
}

fn role_for(manifest: &Manifest, signer: &PublicKey) -> Option<ManagerRole> {
    if manifest
        .governance
        .suspend_keys
        .iter()
        .filter_map(|value| apiary_core::identity::parse_npub(value).ok())
        .any(|key| key == *signer)
    {
        return Some(ManagerRole::Governor);
    }
    manifest.governance.managers.iter().find_map(|manager| {
        apiary_core::identity::parse_npub(&manager.npub)
            .ok()
            .filter(|key| key == signer)
            .map(|_| manager.role)
    })
}

pub fn required_agent_role(method: &str, path_and_query: &str) -> ManagerRole {
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    if method == "GET" {
        return if path.ends_with("/control-tokens") {
            ManagerRole::Governor
        } else {
            ManagerRole::Viewer
        };
    }
    let governor_only = path.ends_with("/manifest")
        || path.contains("/ratify")
        || path.ends_with("/governors")
        || path.contains("/control-token")
        || path.contains("/credential/")
        || path.ends_with("/export")
        || path.ends_with("/connectors/oauth");
    if governor_only {
        return ManagerRole::Governor;
    }
    let operator = path.ends_with("/run")
        || path.ends_with("/active")
        || path.ends_with("/log/publish")
        || path.ends_with("/buzz/post")
        || path.ends_with("/lease/takeover")
        || path.ends_with("/listener")
        || (path.contains("/routines/")
            && (path.ends_with("/run") || path.ends_with("/pause") || path.ends_with("/resume")));
    if operator {
        ManagerRole::Operator
    } else {
        ManagerRole::Editor
    }
}

/// Authorize one per-agent request at the minimum role required by its route.
/// Local signer-less desktop calls retain operator trust; explicit identities
/// are always bound to the target agent's manifest, including in open mode.
pub fn authorize_agent_request(
    state: &AppState,
    signer: Option<PublicKey>,
    manifest: &Manifest,
    method: &str,
    path_and_query: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if state.auth == AuthMode::Open && signer.is_none() {
        return Ok(());
    }
    let required = required_agent_role(method, path_and_query);
    match signer.and_then(|signer| role_for(manifest, &signer)) {
        Some(actual) if actual >= required => Ok(()),
        Some(actual) => Err(crate::err(
            StatusCode::FORBIDDEN,
            format!(
                "agent manager role {actual:?} cannot perform this operation; {required:?} is required"
            )
            .to_ascii_lowercase(),
        )),
        None if signer.is_some() => Err(crate::err(
            StatusCode::FORBIDDEN,
            "signer is not a manager of this agent",
        )),
        None => Err(crate::err(
            StatusCode::UNAUTHORIZED,
            "authentication required",
        )),
    }
}

/// Host-scoped authorization: in nip98 mode the signer must be a listed
/// HOST MANAGER — being a valid nostr key (or even some agent's governor)
/// grants nothing over the host itself. The registry combines bootstrap
/// `--admin` keys with stored managers. Signer-less open-mode requests retain
/// local trust; an explicit signer remains constrained even on the desktop.
pub fn authorize_admin(
    state: &AppState,
    signer: Option<PublicKey>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if state.auth == AuthMode::Open && signer.is_none() {
        return Ok(());
    }
    let managers = state.managers.read().map_err(|_| {
        crate::err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "host manager registry is unavailable",
        )
    })?;
    if managers.is_empty() {
        return Err(crate::err(
            StatusCode::FORBIDDEN,
            "host-scoped operations need a host manager — start once with --admin <npub> to bootstrap one",
        ));
    }
    match signer {
        Some(pk) if managers.contains(&pk) => Ok(()),
        Some(_) => Err(crate::err(
            StatusCode::FORBIDDEN,
            "signer is not a host manager",
        )),
        None => Err(crate::err(
            StatusCode::UNAUTHORIZED,
            "authentication required",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(auth: AuthMode) -> AppState {
        let home = std::env::temp_dir().join(format!(
            "apiary-nip98-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        AppState {
            home,
            passphrase: std::sync::RwLock::new(None),
            remember_passphrase: None,
            forget_passphrase: None,
            automatic_unlock: std::sync::atomic::AtomicBool::new(false),
            auth,
            origin: "http://127.0.0.1:7777".into(),
            token: None,
            internal_token: "test-internal-token".into(),
            control_audit: std::sync::Mutex::new(()),
            control_tokens: std::sync::Mutex::new(()),
            listeners: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_oauth: std::sync::Mutex::new(std::collections::HashMap::new()),
            managers: std::sync::RwLock::new(crate::access::ManagerRegistry::in_memory(Vec::new())),
            supervisor_notes: std::sync::Mutex::new(std::collections::HashMap::new()),
            admitted: std::sync::Mutex::new(std::collections::HashMap::new()),
            decisions: Default::default(),
        }
    }

    fn signed_header(
        keys: &Keys,
        url: &str,
        method: &str,
        body: Option<&[u8]>,
        age_offset: i64,
    ) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + age_offset;
        let mut builder = EventBuilder::new(Kind::Custom(NIP98_KIND), "")
            .tag(Tag::custom("u", vec![url.to_string()]))
            .tag(Tag::custom("method", vec![method.to_string()]));
        if let Some(b) = body {
            builder = builder.tag(Tag::custom(
                "payload",
                vec![format!("{:x}", Sha256::digest(b))],
            ));
        }
        let event = builder
            .custom_created_at(Timestamp::from_secs(now as u64))
            .finalize(keys)
            .unwrap();
        format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(event.as_json())
        )
    }

    fn headers_with(h: String) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert("authorization", h.parse().unwrap());
        m
    }

    #[test]
    fn open_mode_passes_without_header() {
        assert!(check(
            &state(AuthMode::Open),
            &HeaderMap::new(),
            "GET",
            "/api/agents",
            None
        )
        .is_ok());
    }

    #[test]
    fn exact_url_and_method_required() {
        let s = state(AuthMode::Nip98);
        let keys = Keys::generate();
        let h = headers_with(signed_header(
            &keys,
            "http://127.0.0.1:7777/api/agents",
            "GET",
            None,
            0,
        ));
        assert_eq!(
            check(&s, &h, "GET", "/api/agents", None).unwrap(),
            Some(keys.public_key())
        );
        // Suffix-only match is NOT enough (prefix must be the exact origin).
        let h2 = headers_with(signed_header(
            &keys,
            "http://evil.example/api/agents",
            "GET",
            None,
            0,
        ));
        assert!(check(&s, &h2, "GET", "/api/agents", None).is_err());
        // Query must be included in the signed URL.
        assert!(check(&s, &h, "GET", "/api/agents?x=1", None).is_err());
        // Method mismatch.
        assert!(check(&s, &h, "POST", "/api/agents", None).is_err());
        // Stale.
        let h3 = headers_with(signed_header(
            &keys,
            "http://127.0.0.1:7777/api/agents",
            "GET",
            None,
            -300,
        ));
        assert!(check(&s, &h3, "GET", "/api/agents", None).is_err());
    }

    #[test]
    fn body_bearing_requests_require_payload_hash() {
        let s = state(AuthMode::Nip98);
        let keys = Keys::generate();
        let body = br#"{"task":"x"}"#;
        let url = "http://127.0.0.1:7777/api/agents/npub1x/run";
        // Correct payload hash → accepted.
        let h = headers_with(signed_header(&keys, url, "POST", Some(body), 0));
        assert!(check(&s, &h, "POST", "/api/agents/npub1x/run", Some(body)).is_ok());
        // Substituted body → rejected (captured header authorizes nothing else).
        assert!(check(
            &s,
            &h,
            "POST",
            "/api/agents/npub1x/run",
            Some(br#"{"task":"evil"}"#)
        )
        .is_err());
        // Missing payload tag → rejected.
        let h2 = headers_with(signed_header(&keys, url, "POST", None, 0));
        assert!(check(&s, &h2, "POST", "/api/agents/npub1x/run", Some(body)).is_err());
    }

    #[test]
    fn signed_control_token_authenticates_as_the_agent() {
        let s = state(AuthMode::Nip98);
        let keys = Keys::generate();
        let expected = keys.public_key();
        let mut custody = apiary_core::custody::Custody::new();
        let handle = custody.admit(keys);
        let host_id = apiary_runtime::lease::host_id(&s.home);
        let (token, record) = issue_control_token(&custody, &handle, &host_id, 3600).unwrap();
        let token_id = record.id.clone();
        let agent_npub = record.agent.clone();
        register_control_token(&s, record).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        assert_eq!(
            check_control(&s, &headers, "POST", "/mcp", Some(br#"{}"#)).unwrap(),
            Some(expected)
        );

        let mut wrong_host = state(AuthMode::Nip98);
        wrong_host.home =
            std::env::temp_dir().join(format!("apiary-wrong-control-host-{}", std::process::id()));
        assert!(check_control(&wrong_host, &headers, "POST", "/mcp", None).is_err());
        revoke_control_token(&s, &agent_npub, &token_id).unwrap();
        assert!(check_control(&s, &headers, "POST", "/mcp", None).is_err());
        let _ = std::fs::remove_dir_all(&s.home);
    }

    #[test]
    fn agent_manager_roles_are_hierarchical_and_route_specific() {
        use apiary_core::manifest::{ManagerGrant, ManagerRole, Manifest};

        let agent = Keys::generate();
        let governor = Keys::generate();
        let viewer = Keys::generate();
        let operator = Keys::generate();
        let editor = Keys::generate();
        let mut manifest = Manifest::from_yaml(&format!(
            "manifest_version: 1\nidentity:\n  npub: {}\nmemory:\n  log: local\ngovernance:\n  suspend_keys:\n    - {}\n",
            apiary_core::identity::to_npub(&agent.public_key()).unwrap(),
            apiary_core::identity::to_npub(&governor.public_key()).unwrap(),
        ))
        .unwrap();
        manifest.governance.managers = vec![
            ManagerGrant {
                npub: apiary_core::identity::to_npub(&viewer.public_key()).unwrap(),
                role: ManagerRole::Viewer,
            },
            ManagerGrant {
                npub: apiary_core::identity::to_npub(&operator.public_key()).unwrap(),
                role: ManagerRole::Operator,
            },
            ManagerGrant {
                npub: apiary_core::identity::to_npub(&editor.public_key()).unwrap(),
                role: ManagerRole::Editor,
            },
        ];
        manifest.validate().unwrap();
        let s = state(AuthMode::Open);
        assert!(authorize_agent_request(
            &s,
            Some(viewer.public_key()),
            &manifest,
            "GET",
            "/api/agents/x/manifest"
        )
        .is_ok());
        assert!(authorize_agent_request(
            &s,
            Some(viewer.public_key()),
            &manifest,
            "POST",
            "/api/agents/x/run"
        )
        .is_err());
        assert!(authorize_agent_request(
            &s,
            Some(operator.public_key()),
            &manifest,
            "POST",
            "/api/agents/x/run"
        )
        .is_ok());
        assert!(authorize_agent_request(
            &s,
            Some(operator.public_key()),
            &manifest,
            "POST",
            "/api/agents/x/harnesses"
        )
        .is_err());
        assert!(authorize_agent_request(
            &s,
            Some(editor.public_key()),
            &manifest,
            "POST",
            "/api/agents/x/harnesses"
        )
        .is_ok());
        assert!(authorize_agent_request(
            &s,
            Some(editor.public_key()),
            &manifest,
            "PUT",
            "/api/agents/x/manifest"
        )
        .is_err());
        assert!(authorize_agent_request(
            &s,
            Some(governor.public_key()),
            &manifest,
            "PUT",
            "/api/agents/x/manifest"
        )
        .is_ok());
    }

    #[test]
    fn sensitive_agent_routes_require_governor_role() {
        use apiary_core::manifest::ManagerRole;

        assert_eq!(
            required_agent_role("GET", "/api/agents/x/manifest"),
            ManagerRole::Viewer
        );
        assert_eq!(
            required_agent_role("POST", "/api/agents/x/run"),
            ManagerRole::Operator
        );
        assert_eq!(
            required_agent_role("POST", "/api/agents/x/connectors"),
            ManagerRole::Editor
        );
        for (method, path) in [
            ("PUT", "/api/agents/x/manifest"),
            ("POST", "/api/agents/x/ratify"),
            ("POST", "/api/agents/x/credential/seal"),
            ("POST", "/api/agents/x/control-token"),
            ("GET", "/api/agents/x/control-tokens"),
            ("DELETE", "/api/agents/x/control-tokens/deadbeef"),
        ] {
            assert_eq!(required_agent_role(method, path), ManagerRole::Governor);
        }
    }

    #[test]
    fn internal_identity_forwarding_requires_process_secret() {
        let s = state(AuthMode::Nip98);
        let signer = Keys::generate().public_key();
        let signer_npub = apiary_core::identity::to_npub(&signer).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-apiary-internal-token", "wrong".parse().unwrap());
        headers.insert("x-apiary-internal-signer", signer_npub.parse().unwrap());
        assert!(check(&s, &headers, "GET", "/api/agents", None).is_err());
        headers.insert(
            "x-apiary-internal-token",
            "test-internal-token".parse().unwrap(),
        );
        assert_eq!(
            check(&s, &headers, "GET", "/api/agents", None).unwrap(),
            Some(signer)
        );
    }

    #[test]
    fn governor_binding() {
        let s = state(AuthMode::Nip98);
        let gov = Keys::generate().public_key();
        let stranger = Keys::generate().public_key();
        assert!(authorize_governor(&s, Some(gov), &[gov]).is_ok());
        assert!(authorize_governor(&s, Some(stranger), &[gov]).is_err());
        assert!(authorize_governor(&s, None, &[gov]).is_err());
        // Open mode grants local signer-less requests operator trust, but an
        // authenticated agent identity remains bound to its own grants.
        let open = state(AuthMode::Open);
        assert!(authorize_governor(&open, None, &[gov]).is_ok());
        assert!(authorize_governor(&open, Some(gov), &[gov]).is_ok());
        assert!(authorize_governor(&open, Some(stranger), &[gov]).is_err());
    }

    #[test]
    fn host_manager_registry_binds_admin_authority() {
        let manager = Keys::generate().public_key();
        let stranger = Keys::generate().public_key();
        let mut s = state(AuthMode::Nip98);
        s.managers =
            std::sync::RwLock::new(crate::access::ManagerRegistry::in_memory(vec![manager]));
        assert!(authorize_admin(&s, Some(manager)).is_ok());
        assert!(authorize_admin(&s, Some(stranger)).is_err());
        assert!(authorize_admin(&s, None).is_err());

        let mut open = state(AuthMode::Open);
        open.managers =
            std::sync::RwLock::new(crate::access::ManagerRegistry::in_memory(vec![manager]));
        assert!(authorize_admin(&open, None).is_ok());
        assert!(authorize_admin(&open, Some(manager)).is_ok());
        assert!(authorize_admin(&open, Some(stranger)).is_err());
    }
}
