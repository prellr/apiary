//! The AG-UI run stream — SPEC §10 Direction A, running code.
//!
//! POST /api/agents/{npub}/run streams the run as AG-UI events over SSE:
//! RUN_STARTED → STEP/TOOL_CALL events as the loop works → TEXT_MESSAGE_*
//! with the reply → RUN_FINISHED. Tokens stream coarsely (our providers are
//! non-streaming today); signed checkpoints stay in the log — this stream
//! is presence, the log is truth.

use crate::{admit_agent, agent_ctx, err, load_manifest, nip98, App};
use apiary_core::{ceremony, log::EpisodicLog};
use apiary_runtime::routing::TaskContext;
use apiary_runtime::runner::{run_task_observed, RunEvent};
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse,
    },
};
use serde_json::json;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt;

#[derive(serde::Deserialize)]
pub struct RunBody {
    task: String,
    #[serde(default)]
    class: Option<String>,
    #[serde(default)]
    data_class: Option<String>,
    /// Operator-supplied media (a companion's clipboard image, a screen
    /// grab): same shape as channel attachments, same host caps.
    #[serde(default)]
    attachments: Vec<RunAttachment>,
}

#[derive(serde::Deserialize)]
pub struct RunAttachment {
    #[serde(default = "default_kind")]
    kind: String,
    media_type: String,
    base64: String,
    #[serde(default)]
    duration_secs: Option<f32>,
}

fn default_kind() -> String {
    "image".into()
}

fn to_attachments(v: Vec<RunAttachment>) -> Vec<apiary_runtime::presence::Attachment> {
    use apiary_runtime::presence::{Attachment, MAX_ATTACHMENTS, MAX_ATTACHMENT_BYTES};
    v.into_iter()
        .filter(|a| (a.base64.len() as u64) * 3 / 4 <= MAX_ATTACHMENT_BYTES)
        .filter_map(|a| match a.kind.as_str() {
            "image" => Some(Attachment::Image {
                media_type: a.media_type,
                base64: a.base64,
            }),
            "audio" => Some(Attachment::Audio {
                media_type: a.media_type,
                base64: a.base64,
                duration_secs: a.duration_secs,
            }),
            _ => None,
        })
        .take(MAX_ATTACHMENTS)
        .collect()
}

fn agui(name: &str, mut fields: serde_json::Value) -> SseEvent {
    fields["type"] = json!(name);
    SseEvent::default().data(fields.to_string())
}

pub async fn run_stream(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let signer = match nip98::check(&state, &headers, "POST", &pq, Some(&raw_body)) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let body: RunBody = match serde_json::from_slice(&raw_body) {
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
    let suspend_keys = crate::suspend_pks(&manifest);
    // Only a governor may make the agent act.
    if let Err(e) = nip98::authorize_governor(&state, signer, &suspend_keys) {
        return e.into_response();
    }
    // Ratification gate — verified signatures, both parties, current hash.
    let agent_pk = match apiary_core::identity::parse_npub(&npub) {
        Ok(pk) => pk,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    match ceremony::is_ratified(&EpisodicLog::open(&dir), &raw, &agent_pk, &suspend_keys) {
        Ok(true) => {}
        _ => {
            return err(
                StatusCode::CONFLICT,
                "manifest is not ratified — amendments need re-ratification before the agent runs",
            )
            .into_response()
        }
    }
    let (custody, handle) = match admit_agent(&state, &ks, &npub) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
    };

    let run_id = format!(
        "run-{:x}",
        std::process::id() as u64 ^ std::ptr::addr_of!(state) as u64
    );
    let thread_id = npub.clone();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<SseEvent>();

    let _ = tx.send(agui(
        "RUN_STARTED",
        json!({"threadId": thread_id, "runId": run_id}),
    ));

    let ctx = TaskContext {
        attachments: to_attachments(body.attachments),
        task_class: body.class.clone(),
        data_class: body.data_class.clone(),
        tokens_per_run: None,
    };
    let task = body.task.clone();
    let run_id2 = run_id.clone();
    let thread_id2 = thread_id.clone();
    let tx2 = tx.clone();

    tokio::task::spawn_blocking(move || {
        let msg_id = format!("{run_id2}-msg");
        // Streamed deltas open the message; the completion branch then
        // only closes it (no duplicate content).
        let streamed = std::sync::atomic::AtomicBool::new(false);
        let observer = |e: RunEvent| {
            let _ = match e {
                RunEvent::TextDelta { text } => {
                    if !streamed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        let _ = tx2.send(agui(
                            "TEXT_MESSAGE_START",
                            json!({"messageId": msg_id, "role": "assistant"}),
                        ));
                    }
                    tx2.send(agui(
                        "TEXT_MESSAGE_CONTENT",
                        json!({"messageId": msg_id, "delta": text}),
                    ))
                }
                RunEvent::Started { slot, model } => tx2.send(agui(
                    "STEP_STARTED",
                    json!({"stepName": format!("infer:{slot}/{model}")}),
                )),
                RunEvent::ToolCallStarted { name, args } => {
                    let _ = tx2.send(agui(
                        "TOOL_CALL_START",
                        json!({"toolCallId": name.clone(), "toolCallName": name}),
                    ));
                    tx2.send(agui(
                        "TOOL_CALL_ARGS",
                        json!({"toolCallId": "", "delta": args.to_string()}),
                    ))
                }
                RunEvent::ToolCallFinished { name, ok, detail } => tx2.send(agui(
                    "TOOL_CALL_END",
                    json!({"toolCallId": name, "ok": ok, "detail": detail}),
                )),
                RunEvent::Finished { .. } => Ok(()), // handled below with the result
            };
        };
        let result = run_task_observed(
            &manifest,
            &dir,
            &custody,
            &handle,
            &task,
            &ctx,
            Some(&observer),
        );
        match result {
            Ok(out) => {
                if !streamed.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = tx2.send(agui(
                        "TEXT_MESSAGE_START",
                        json!({"messageId": msg_id, "role": "assistant"}),
                    ));
                    let _ = tx2.send(agui(
                        "TEXT_MESSAGE_CONTENT",
                        json!({"messageId": msg_id, "delta": out.completion.text}),
                    ));
                }
                let _ = tx2.send(agui("TEXT_MESSAGE_END", json!({"messageId": msg_id})));
                let _ = tx2.send(agui(
                    "CUSTOM",
                    json!({"name": "apiary.checkpoint", "value": {
                        "log_event": out.log_event_id,
                        "slot": out.slot,
                        "model": out.completion.model,
                        "outcome": out.completion.outcome,
                        "input_tokens": out.completion.input_tokens,
                        "output_tokens": out.completion.output_tokens,
                    }}),
                ));
                let _ = tx2.send(agui(
                    "RUN_FINISHED",
                    json!({"threadId": thread_id2, "runId": run_id2}),
                ));
            }
            Err(e) => {
                let _ = tx2.send(agui("RUN_ERROR", json!({"message": e.to_string()})));
            }
        }
    });

    let stream = UnboundedReceiverStream::new(rx).map(Ok::<_, std::convert::Infallible>);
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}
