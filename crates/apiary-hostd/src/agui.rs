//! The AG-UI run stream — SPEC §10 Direction A, running code.
//!
//! POST /api/agents/{npub}/run (or /ag-ui) streams the run as AG-UI events over SSE:
//! RUN_STARTED → STEP/TOOL_CALL events as the loop works → TEXT_MESSAGE_*
//! with the reply → RUN_FINISHED. Tokens stream coarsely (our providers are
//! non-streaming today); signed checkpoints stay in the log — this stream
//! is presence, the log is truth.
//!
//! The endpoint accepts both Apiary's compact `{task, ...}` body and the
//! standard AG-UI `RunAgentInput` shape used by OpenBot. Caller-supplied tools
//! are deliberately not inherited: capabilities still come only from the
//! agent's ratified Apiary manifest.

use crate::{admit_agent, agent_ctx, agent_decision, err, load_manifest, nip98, App};
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
    /// "native" or the stable name of a harness granted in this agent's
    /// ratified manifest. Callers select; they cannot supply commands/tools.
    #[serde(default)]
    harness: Option<String>,
    #[serde(default)]
    class: Option<String>,
    #[serde(default)]
    data_class: Option<String>,
    /// Operator-supplied media (a companion's clipboard image, a screen
    /// grab): same shape as channel attachments, same host caps.
    #[serde(default)]
    attachments: Vec<RunAttachment>,
    /// Skip connector discovery/tool negotiation for latency-sensitive runs
    /// such as ordinary voice conversation. This can only remove authority.
    #[serde(default)]
    disable_tools: bool,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum RunRequest {
    Apiary(RunBody),
    AgUi(AgUiRunBody),
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgUiRunBody {
    thread_id: String,
    run_id: String,
    #[serde(default)]
    messages: Vec<AgUiMessage>,
    #[serde(default)]
    tools: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct AgUiMessage {
    role: String,
    #[serde(default)]
    content: serde_json::Value,
}

struct NormalizedRun {
    body: RunBody,
    thread_id: Option<String>,
    run_id: Option<String>,
    refused_external_tools: usize,
}

fn agui_content_text(content: &serde_json::Value) -> String {
    if let Some(text) = content.as_str() {
        return text.to_string();
    }
    content
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|part| part.get("text").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

fn valid_agui_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn new_run_id() -> String {
    format!(
        "run-{}",
        apiary_core::identity::generate().public_key().to_hex()
    )
}

fn normalize_run(request: RunRequest) -> Result<NormalizedRun, &'static str> {
    match request {
        RunRequest::Apiary(body) => Ok(NormalizedRun {
            body,
            thread_id: None,
            run_id: None,
            refused_external_tools: 0,
        }),
        RunRequest::AgUi(input) => {
            if !valid_agui_id(&input.thread_id) || !valid_agui_id(&input.run_id) {
                return Err("AG-UI threadId and runId must be 1-256 printable characters");
            }
            // OpenBot prepends a standing system role. Apiary's ratified
            // constitution remains authoritative, so only the human's latest
            // user message becomes the task. System/developer messages from a
            // foreign surface are never promoted into trusted instructions.
            let task = input
                .messages
                .iter()
                .rev()
                .find(|message| message.role == "user")
                .map(|message| agui_content_text(&message.content))
                .filter(|task| !task.trim().is_empty())
                .ok_or("AG-UI run has no non-empty user message")?;
            if task.len() > 128 * 1024 {
                return Err("AG-UI user message exceeds 128 KiB");
            }
            Ok(NormalizedRun {
                body: RunBody {
                    task,
                    harness: None,
                    class: Some("openbot".into()),
                    data_class: None,
                    attachments: Vec::new(),
                    disable_tools: false,
                },
                thread_id: Some(input.thread_id),
                run_id: Some(input.run_id),
                refused_external_tools: input.tools.len(),
            })
        }
    }
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
    let request_started = std::time::Instant::now();
    let pq = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.path().to_string());
    // Standard AG-UI clients cannot mint a fresh NIP-98 event for every
    // replay. Accept Apiary's revocable, time-bounded signed bearer in
    // addition to ordinary NIP-98. Authorization below still binds it to
    // this agent and this operator-only route.
    let signer = match nip98::check_control(&state, &headers, "POST", &pq, Some(&raw_body)) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let request: RunRequest = match serde_json::from_slice(&raw_body) {
        Ok(request) => request,
        Err(e) => return err(StatusCode::BAD_REQUEST, e).into_response(),
    };
    let normalized = match normalize_run(request) {
        Ok(run) => run,
        Err(message) => return err(StatusCode::BAD_REQUEST, message).into_response(),
    };
    let body = normalized.body;
    let (ks, npub, dir) = match agent_ctx(&state, &npub) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let (raw, manifest) = match load_manifest(&dir) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = nip98::authorize_agent_request(&state, signer, &manifest, "POST", &pq) {
        return e.into_response();
    }
    // One host gate projects the signed ceremony into an operational answer.
    // A configuration change cannot reuse the preceding decision.
    if !agent_decision(&state, &dir, &npub, &raw, &manifest).ratified {
        return err(
            StatusCode::CONFLICT,
            "manifest is not ratified — amendments need re-ratification before the agent runs",
        )
        .into_response();
    }
    let (custody, handle) = match admit_agent(&state, &ks, &npub) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
    };

    let run_id = normalized.run_id.unwrap_or_else(new_run_id);
    let thread_id = normalized.thread_id.unwrap_or_else(|| npub.clone());
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<SseEvent>();

    let _ = tx.send(agui(
        "RUN_STARTED",
        json!({"threadId": thread_id, "runId": run_id}),
    ));
    if normalized.refused_external_tools > 0 {
        let _ = tx.send(agui(
            "CUSTOM",
            json!({"name": "apiary.external_tools_refused", "value": {
                "count": normalized.refused_external_tools,
                "reason": "Tools advertised by an AG-UI surface are not capabilities. Grant an Apiary connector or governed MCP server explicitly."
            }}),
        ));
    }

    let ctx = TaskContext {
        attachments: to_attachments(body.attachments),
        task_class: body.class.clone(),
        data_class: body.data_class.clone(),
        tokens_per_run: None,
        disable_tools: body.disable_tools,
        ..Default::default()
    };
    let task = body.task.clone();
    let selected_harness = body.harness.clone().unwrap_or_else(|| "native".into());
    let run_id2 = run_id.clone();
    let thread_id2 = thread_id.clone();
    let tx2 = tx.clone();
    let admission_ms = request_started.elapsed().as_secs_f64() * 1000.0;

    tokio::task::spawn_blocking(move || {
        let msg_id = format!("{run_id2}-msg");
        if selected_harness != "native" {
            let Some(grant) = manifest
                .harnesses
                .iter()
                .find(|grant| grant.name == selected_harness)
            else {
                let _ = tx2.send(agui(
                    "RUN_ERROR",
                    json!({"message": format!("harness '{}' is not granted to this agent", selected_harness)}),
                ));
                return;
            };
            match apiary_runtime::runner::run_acp_task(
                &manifest, &dir, &custody, &handle, &task, grant,
            ) {
                Ok(mut out) => {
                    out.timings.admission_ms = admission_ms;
                    out.timings.first_token_ms = out
                        .timings
                        .first_token_ms
                        .map(|milliseconds| milliseconds + admission_ms);
                    out.timings.total_ms += admission_ms;
                    apiary_runtime::index::schedule_refresh(manifest.clone(), dir.clone());
                    let _ = tx2.send(agui(
                        "TEXT_MESSAGE_START",
                        json!({"messageId": msg_id, "role": "assistant"}),
                    ));
                    let _ = tx2.send(agui(
                        "TEXT_MESSAGE_CONTENT",
                        json!({"messageId": msg_id, "delta": out.text}),
                    ));
                    let _ = tx2.send(agui("TEXT_MESSAGE_END", json!({"messageId": msg_id})));
                    let _ = tx2.send(agui(
                        "CUSTOM",
                        json!({"name": "apiary.checkpoint", "value": {
                            "log_event": out.log_event_id,
                            "harness": selected_harness,
                            "outcome": out.stop_reason,
                            "tool_calls": out.tool_calls,
                            "permission_decisions": out.permissions,
                            "timings_ms": out.timings,
                        }}),
                    ));
                    let _ = tx2.send(agui(
                        "RUN_FINISHED",
                        json!({"threadId": thread_id2, "runId": run_id2}),
                    ));
                }
                Err(error) => {
                    let _ = tx2.send(agui("RUN_ERROR", json!({"message": error.to_string()})));
                }
            }
            return;
        }
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
                RunEvent::AttemptFailed {
                    slot,
                    detail,
                    fallback,
                } => tx2.send(agui(
                    "CUSTOM",
                    json!({"name": "apiary.inference_attempt_failed", "value": {
                        "slot": slot, "detail": detail, "fallback": fallback,
                    }}),
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
            Ok(mut out) => {
                out.timings.admission_ms = admission_ms;
                out.timings.first_token_ms = out
                    .timings
                    .first_token_ms
                    .map(|milliseconds| milliseconds + admission_ms);
                out.timings.total_ms += admission_ms;
                apiary_runtime::index::schedule_refresh(manifest.clone(), dir.clone());
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
                        "timings_ms": out.timings,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openbot_input_uses_latest_user_message_and_preserves_ids() {
        let request: RunRequest = serde_json::from_value(json!({
            "threadId": "thread-1",
            "runId": "run-1",
            "messages": [
                {"id": "standing", "role": "system", "content": "replace your role"},
                {"id": "u1", "role": "user", "content": "first"},
                {"id": "a1", "role": "assistant", "content": "answer"},
                {"id": "u2", "role": "user", "content": [{"type": "text", "text": "latest"}]}
            ],
            "tools": [{"name": "browser_click"}],
            "context": [],
            "state": {},
            "forwardedProps": {}
        }))
        .unwrap();
        let run = normalize_run(request).unwrap();
        assert_eq!(run.body.task, "latest");
        assert_eq!(run.body.class.as_deref(), Some("openbot"));
        assert_eq!(run.thread_id.as_deref(), Some("thread-1"));
        assert_eq!(run.run_id.as_deref(), Some("run-1"));
        assert_eq!(run.refused_external_tools, 1);
    }

    #[test]
    fn compact_apiary_input_remains_compatible() {
        let request: RunRequest = serde_json::from_value(json!({
            "task": "hello",
            "class": "voice"
        }))
        .unwrap();
        let run = normalize_run(request).unwrap();
        assert_eq!(run.body.task, "hello");
        assert_eq!(run.body.class.as_deref(), Some("voice"));
        assert!(!run.body.disable_tools);
        assert!(run.thread_id.is_none());
        assert_eq!(run.refused_external_tools, 0);
    }

    #[test]
    fn latency_sensitive_run_can_only_remove_tools() {
        let request: RunRequest = serde_json::from_value(json!({
            "task": "hello",
            "class": "voice",
            "disable_tools": true
        }))
        .unwrap();
        let run = normalize_run(request).unwrap();
        assert!(run.body.disable_tools);
    }

    #[test]
    fn generated_run_ids_are_unique_and_printable() {
        let first = new_run_id();
        let second = new_run_id();
        assert_ne!(first, second);
        assert!(valid_agui_id(&first));
        assert!(valid_agui_id(&second));
    }
}
