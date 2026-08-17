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
const FRESHNESS_SECS: u64 = 60;

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
        let ok = presented.len() == expected.len()
            && presented
                .bytes()
                .zip(expected.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
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
/// HOST ADMIN — being a valid nostr key (or even some agent's governor)
/// grants nothing over the host itself. Open mode remains local trust.
pub fn authorize_admin(
    state: &AppState,
    signer: Option<PublicKey>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if state.auth == AuthMode::Open {
        return Ok(());
    }
    if state.admins.is_empty() {
        return Err(crate::err(
            StatusCode::FORBIDDEN,
            "host-scoped operations need a host administrator — start the daemon with --admin <npub>",
        ));
    }
    match signer {
        Some(pk) if state.admins.contains(&pk) => Ok(()),
        Some(_) => Err(crate::err(
            StatusCode::FORBIDDEN,
            "signer is not a host administrator",
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
            auth,
            origin: "http://127.0.0.1:7777".into(),
            token: None,
            listeners: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_oauth: std::sync::Mutex::new(std::collections::HashMap::new()),
            admins: Vec::new(),
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
}
