//! Host event bus — a live window for companions (apiary-voice) onto
//! things the host does on its own: a routine delivered to `companion`,
//! later a mention answered, a lease lost. `GET /api/events` is an SSE
//! stream (desktop token or NIP-98 governor); events are JSON lines
//! `{type, npub, at, ...}`. Nothing is queued for absent subscribers —
//! this is a subscription, not a mailbox; the signed log is the record.

use crate::App;
use axum::extract::{OriginalUri, State};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::IntoResponse;
use serde_json::json;
use std::sync::OnceLock;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

fn bus() -> &'static broadcast::Sender<serde_json::Value> {
    static BUS: OnceLock<broadcast::Sender<serde_json::Value>> = OnceLock::new();
    BUS.get_or_init(|| broadcast::channel(256).0)
}

/// Publish an event; returns how many subscribers received it (0 = no
/// companion is listening — callers may record "undelivered").
pub fn publish(mut ev: serde_json::Value) -> usize {
    if ev.get("at").is_none() {
        ev["at"] = json!(chrono::Utc::now().to_rfc3339());
    }
    bus().send(ev).unwrap_or(0)
}

pub fn subscriber_count() -> usize {
    bus().receiver_count()
}

/// GET /api/events
pub async fn events(
    State(state): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    if let Err(e) = crate::nip98::check(&state, &headers, "GET", &pq, None) {
        return e.into_response();
    }
    let rx = bus().subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|r| match r {
        Ok(v) => Some(Ok::<_, std::convert::Infallible>(
            SseEvent::default()
                .event(v["type"].as_str().unwrap_or("event"))
                .data(v.to_string()),
        )),
        Err(_) => None, // lagged: drop, the log is the record
    });
    let hello = tokio_stream::once(Ok::<_, std::convert::Infallible>(
        SseEvent::default()
            .event("hello")
            .data(json!({"type": "hello", "at": chrono::Utc::now().to_rfc3339()}).to_string()),
    ));
    Sse::new(hello.chain(stream))
        .keep_alive(KeepAlive::default())
        .into_response()
}
