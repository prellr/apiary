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
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use nostr::prelude::*;
use sha2::{Digest, Sha256};

const NIP98_KIND: u16 = 27235;
const CONTROL_TOKEN_KIND: u16 = 27236;
const FRESHNESS_SECS: u64 = 60;
const MAX_CONTROL_TOKEN_SECS: u64 = 90 * 24 * 60 * 60;

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
) -> Result<(String, u64), apiary_core::Error> {
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
    Ok((format!("apiary_{encoded}"), expires_at))
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
    if state.auth == AuthMode::Open {
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

/// Host-scoped authorization: in nip98 mode the signer must be a listed
/// HOST MANAGER — being a valid nostr key (or even some agent's governor)
/// grants nothing over the host itself. The registry combines bootstrap
/// `--admin` keys with stored managers. Open mode remains local trust.
pub fn authorize_admin(
    state: &AppState,
    signer: Option<PublicKey>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if state.auth == AuthMode::Open {
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
    use std::path::PathBuf;

    fn state(auth: AuthMode) -> AppState {
        AppState {
            home: PathBuf::from("/tmp"),
            passphrase: std::sync::RwLock::new(None),
            remember_passphrase: None,
            forget_passphrase: None,
            automatic_unlock: std::sync::atomic::AtomicBool::new(false),
            auth,
            origin: "http://127.0.0.1:7777".into(),
            token: None,
            internal_token: "test-internal-token".into(),
            control_audit: std::sync::Mutex::new(()),
            listeners: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_oauth: std::sync::Mutex::new(std::collections::HashMap::new()),
            managers: std::sync::RwLock::new(crate::access::ManagerRegistry::in_memory(Vec::new())),
            supervisor_notes: std::sync::Mutex::new(std::collections::HashMap::new()),
            admitted: std::sync::Mutex::new(std::collections::HashMap::new()),
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
        let (token, _) = issue_control_token(&custody, &handle, &host_id, 3600).unwrap();
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
        // Open mode: local trust, no binding.
        assert!(authorize_governor(&state(AuthMode::Open), None, &[gov]).is_ok());
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
    }
}
