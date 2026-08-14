//! Minimal sync nostr relay client — publish and fetch over one WebSocket.
//! Shared by the nostr-publish connector and the log publisher. The daemon's
//! async relay pool (SPEC §2) supersedes this when it lands; the wire
//! behavior stays the same.

use nostr::prelude::*;
use serde_json::{json, Value};
use tungstenite::Message;

/// Publish one event; wait for the relay's OK. Idempotent for a given event
/// id — relays deduplicate.
pub fn publish(url: &str, event: &Event) -> Result<String, crate::Error> {
    let (mut socket, _) = tungstenite::connect(url)
        .map_err(|e| crate::Error::Provider(format!("connect {url}: {e}")))?;
    let frame = json!(["EVENT", serde_json::from_str::<Value>(&event.as_json())?]);
    socket
        .send(Message::Text(frame.to_string().into()))
        .map_err(|e| crate::Error::Provider(format!("send: {e}")))?;
    for _ in 0..10 {
        let msg = socket
            .read()
            .map_err(|e| crate::Error::Provider(format!("read: {e}")))?;
        if let Message::Text(text) = msg {
            let v: Value = serde_json::from_str(&text)?;
            if v.get(0).and_then(|t| t.as_str()) == Some("OK")
                && v.get(1).and_then(|id| id.as_str()) == Some(&event.id.to_hex())
            {
                let accepted = v.get(2).and_then(|b| b.as_bool()).unwrap_or(false);
                let detail = v.get(3).and_then(|m| m.as_str()).unwrap_or("");
                let _ = socket.close(None);
                return if accepted || detail.starts_with("duplicate") {
                    Ok(if detail.is_empty() {
                        "accepted".into()
                    } else {
                        detail.into()
                    })
                } else {
                    Err(crate::Error::Provider(format!("rejected: {detail}")))
                };
            }
        }
    }
    Err(crate::Error::Provider("no OK response".into()))
}

/// Fetch events matching a filter (REQ … EOSE). Signatures are verified;
/// unverifiable events are dropped, not returned.
pub fn fetch(url: &str, filter: Value) -> Result<Vec<Event>, crate::Error> {
    let (mut socket, _) = tungstenite::connect(url)
        .map_err(|e| crate::Error::Provider(format!("connect {url}: {e}")))?;
    let sub = "apiary-fetch";
    let frame = json!(["REQ", sub, filter]);
    socket
        .send(Message::Text(frame.to_string().into()))
        .map_err(|e| crate::Error::Provider(format!("send: {e}")))?;
    let mut out = Vec::new();
    for _ in 0..500 {
        let msg = socket
            .read()
            .map_err(|e| crate::Error::Provider(format!("read: {e}")))?;
        if let Message::Text(text) = msg {
            let v: Value = serde_json::from_str(&text)?;
            match v.get(0).and_then(|t| t.as_str()) {
                Some("EVENT") if v.get(1).and_then(|s| s.as_str()) == Some(sub) => {
                    if let Some(raw) = v.get(2) {
                        if let Ok(event) = Event::from_json(raw.to_string()) {
                            if event.verify().is_ok() {
                                out.push(event);
                            }
                        }
                    }
                }
                Some("EOSE") => break,
                _ => {}
            }
        }
    }
    let _ = socket.close(None);
    Ok(out)
}
