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
    response::{sse::{Event as SseEvent, KeepAlive, Sse}, IntoResponse},
    Json,
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
}

fn agui(name: &str, mut fields: serde_json::Value) -> SseEvent {
    fields["type"] = json!(name);
    SseEvent::default().data(fields.to_string())
}

pub async fn run_stream(
    State(state): State<App>,
    AxPath(npub): AxPath<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RunBody>,
) -> impl IntoResponse {
    if let Err(e) = nip98::check(&state, &headers, &format!("/api/agents/{npub}/run"), "POST") {
        return e.into_response();
    }
    let (ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let (raw, manifest) = match load_manifest(&dir) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    // Ratification gate — same constitution rule as the CLI.
    let suspend_keys: Vec<_> = manifest
        .governance
        .suspend_keys
        .iter()
        .filter_map(|k| apiary_core::identity::parse_npub(k).ok())
        .collect();
    match ceremony::is_ratified(&EpisodicLog::open(&dir), &raw, &suspend_keys) {
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

    let run_id = format!("run-{:x}", std::process::id() as u64 ^ std::ptr::addr_of!(state) as u64);
    let thread_id = npub.clone();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<SseEvent>();

    let _ = tx.send(agui("RUN_STARTED", json!({"threadId": thread_id, "runId": run_id})));

    let ctx = TaskContext { task_class: body.class.clone(), data_class: body.data_class.clone() };
    let task = body.task.clone();
    let run_id2 = run_id.clone();
    let thread_id2 = thread_id.clone();
    let tx2 = tx.clone();

    tokio::task::spawn_blocking(move || {
        let msg_id = format!("{run_id2}-msg");
        let observer = |e: RunEvent| {
            let _ = match e {
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
            &manifest, &dir, &custody, &handle, &task, &ctx, Some(&observer),
        );
        match result {
            Ok(out) => {
                let _ = tx2.send(agui("TEXT_MESSAGE_START", json!({"messageId": msg_id, "role": "assistant"})));
                let _ = tx2.send(agui("TEXT_MESSAGE_CONTENT", json!({"messageId": msg_id, "delta": out.completion.text})));
                let _ = tx2.send(agui("TEXT_MESSAGE_END", json!({"messageId": msg_id})));
                let _ = tx2.send(agui("CUSTOM", json!({"name": "apiary.checkpoint", "value": {
                    "log_event": out.log_event_id,
                    "slot": out.slot,
                    "model": out.completion.model,
                    "outcome": out.completion.outcome,
                    "input_tokens": out.completion.input_tokens,
                    "output_tokens": out.completion.output_tokens,
                }})));
                let _ = tx2.send(agui("RUN_FINISHED", json!({"threadId": thread_id2, "runId": run_id2})));
            }
            Err(e) => {
                let _ = tx2.send(agui("RUN_ERROR", json!({"message": e.to_string()})));
            }
        }
    });

    let stream = UnboundedReceiverStream::new(rx).map(Ok::<_, std::convert::Infallible>);
    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}
