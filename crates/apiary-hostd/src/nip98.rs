//! NIP-98 HTTP auth — the nostr×AG-UI seam (SPEC §10): a signed ephemeral
//! event in the Authorization header binds the request to an npub. No
//! passwords, no bearer tokens, no account table.

use crate::{AppState, AuthMode};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use nostr::prelude::*;

const NIP98_KIND: u16 = 27235;
const FRESHNESS_SECS: u64 = 60;

/// Enforce the daemon's auth mode for a request. In `open` mode this is a
/// no-op (localhost dev); in `nip98` mode the Authorization header must
/// carry a valid, fresh, signed kind-27235 event whose u/method tags match.
pub fn check(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    method: &str,
) -> Result<Option<PublicKey>, (StatusCode, Json<serde_json::Value>)> {
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
    let at = event.created_at.as_secs();
    if now.abs_diff(at) > FRESHNESS_SECS {
        return Err(fail("stale event (replay window exceeded)"));
    }

    let tag = |name: &str| {
        event.tags.iter().find_map(|t| {
            let s = t.as_slice();
            (s.first().map(String::as_str) == Some(name)).then(|| s.get(1).cloned())?
        })
    };
    // The u tag must END with our path — clients sign the full URL, and the
    // daemon may sit behind localhost or a hostname it can't see.
    match tag("u") {
        Some(u) if u.split('?').next().unwrap_or("").ends_with(path) => {}
        _ => return Err(fail("u tag does not match request path")),
    }
    if tag("method").as_deref() != Some(method) {
        return Err(fail("method tag mismatch"));
    }
    Ok(Some(event.pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn state(auth: AuthMode) -> AppState {
        AppState { home: PathBuf::from("/tmp"), passphrase: None, auth }
    }

    fn signed_header(keys: &Keys, url: &str, method: &str, age_offset: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + age_offset;
        let event = EventBuilder::new(Kind::Custom(NIP98_KIND), "")
            .tag(Tag::custom("u", vec![url.to_string()]))
            .tag(Tag::custom("method", vec![method.to_string()]))
            .custom_created_at(Timestamp::from_secs(now as u64))
            .finalize(keys)
            .unwrap();
        format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(event.as_json())
        )
    }

    #[test]
    fn open_mode_passes_without_header() {
        assert!(check(&state(AuthMode::Open), &HeaderMap::new(), "/api/agents", "GET").is_ok());
    }

    #[test]
    fn nip98_verifies_and_rejects() {
        let s = state(AuthMode::Nip98);
        let keys = Keys::generate();

        // No header → rejected.
        assert!(check(&s, &HeaderMap::new(), "/api/agents", "GET").is_err());

        // Valid header → accepted, pubkey returned.
        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            signed_header(&keys, "http://localhost:7777/api/agents", "GET", 0).parse().unwrap(),
        );
        let who = check(&s, &h, "/api/agents", "GET").unwrap();
        assert_eq!(who, Some(keys.public_key()));

        // Wrong path → rejected.
        assert!(check(&s, &h, "/api/other", "GET").is_err());
        // Wrong method → rejected.
        assert!(check(&s, &h, "/api/agents", "POST").is_err());

        // Stale → rejected.
        let mut h2 = HeaderMap::new();
        h2.insert(
            "authorization",
            signed_header(&keys, "http://localhost:7777/api/agents", "GET", -300).parse().unwrap(),
        );
        assert!(check(&s, &h2, "/api/agents", "GET").is_err());
    }
}
