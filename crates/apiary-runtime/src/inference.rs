//! Inference providers — each slot in the manifest pool binds to one of
//! these. Raw HTTP: Rust has no official Anthropic SDK, so the Anthropic
//! provider speaks the Messages API directly.

use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Completion {
    pub text: String,
    pub model: String,
    /// "ok" | "refusal" | raw stop_reason
    pub outcome: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// An image attached to the task — base64 payload plus media type.
/// Providers with vision include it in the user content; providers
/// without simply cannot see it (the framing text says images were
/// attached, so the model can say so honestly).
#[derive(Debug, Clone)]
pub struct ImageInput {
    pub media_type: String,
    pub base64: String,
}

/// Flat per-image token estimate for budget pre-checks (a ~1MP photo
/// costs on the order of 1.3–1.6k input tokens on vision models).
pub const IMAGE_TOKEN_ESTIMATE: u64 = 1600;

/// Anthropic-shape user content: image blocks then the text.
fn anthropic_user_content(prompt: &str, images: &[ImageInput]) -> serde_json::Value {
    if images.is_empty() {
        return json!(prompt);
    }
    let mut blocks: Vec<serde_json::Value> = images
        .iter()
        .map(|i| {
            json!({"type": "image", "source": {
                "type": "base64", "media_type": i.media_type, "data": i.base64}})
        })
        .collect();
    blocks.push(json!({"type": "text", "text": prompt}));
    json!(blocks)
}

/// OpenAI-dialect user content: data-URL image parts then the text.
fn openai_user_content(prompt: &str, images: &[ImageInput]) -> serde_json::Value {
    if images.is_empty() {
        return json!(prompt);
    }
    let mut parts: Vec<serde_json::Value> = images
        .iter()
        .map(|i| {
            json!({"type": "image_url", "image_url": {
                "url": format!("data:{};base64,{}", i.media_type, i.base64)}})
        })
        .collect();
    parts.push(json!({"type": "text", "text": prompt}));
    json!(parts)
}

/// Dispatch callback: (tool_name, args) → result string. The HOST owns this —
/// it checks caps, logs the call, and executes through custody. The model's
/// tool_use blocks are requests into it, never direct capability.
pub type ToolDispatch<'a> =
    &'a mut dyn FnMut(&str, &serde_json::Value) -> Result<String, crate::Error>;

pub trait Provider {
    /// `max_tokens` is the spend-authority clamp: the provider must not be
    /// asked for more output than the run's reserved budget allows.
    fn complete(
        &self,
        model: &str,
        system: &str,
        prompt: &str,
        images: &[ImageInput],
        max_tokens: u64,
    ) -> Result<Completion, crate::Error>;

    /// Multi-turn tool loop under a cumulative token budget: each iteration
    /// is clamped to what remains, and the loop stops (outcome
    /// "budget-exhausted") rather than overrunning. Providers without tool
    /// support fall back to a plain completion and flag it.
    #[allow(clippy::too_many_arguments)] // the run's full surface, deliberately explicit
    fn complete_with_tools(
        &self,
        model: &str,
        system: &str,
        prompt: &str,
        images: &[ImageInput],
        tools: &[crate::connector::ToolDef],
        _dispatch: ToolDispatch,
        budget_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        let mut c = self.complete(model, system, prompt, images, budget_tokens)?;
        if !tools.is_empty() {
            c.outcome = format!("{} (provider has no tool support; tools unused)", c.outcome);
        }
        Ok(c)
    }
}

/// Conservative token estimate for budget pre-checks: ~3 chars per token
/// errs on the refusing side for English prose and JSON alike.
pub fn estimate_tokens(text: &str) -> u64 {
    (text.len() as u64) / 3 + 1
}

/// Anthropic Messages API over raw HTTP.
///
/// Auth is either an API key (`x-api-key`) or an OAuth bearer token
/// (`Authorization: Bearer` + the `oauth-2025-04-20` beta header). Thinking
/// is deliberately unconfigured — current models run adaptive thinking by
/// default, and `budget_tokens`/sampling params are rejected on them.
pub struct AnthropicProvider {
    auth: AnthropicAuth,
    base_url: String,
}

pub enum AnthropicAuth {
    ApiKey(Zeroizing<String>),
    Bearer(Zeroizing<String>),
}

impl AnthropicProvider {
    pub fn new(auth: AnthropicAuth) -> Self {
        Self {
            auth,
            base_url: "https://api.anthropic.com".into(),
        }
    }

    /// Resolve auth from the environment: ANTHROPIC_API_KEY, then
    /// ANTHROPIC_AUTH_TOKEN. (A sealed manifest credential, decrypted by the
    /// caller through custody, comes in via `AnthropicAuth` directly.)
    pub fn from_env() -> Option<Self> {
        if let Ok(k) = std::env::var("ANTHROPIC_API_KEY") {
            if !k.is_empty() {
                return Some(Self::new(AnthropicAuth::ApiKey(Zeroizing::new(k))));
            }
        }
        if let Ok(t) = std::env::var("ANTHROPIC_AUTH_TOKEN") {
            if !t.is_empty() {
                return Some(Self::new(AnthropicAuth::Bearer(Zeroizing::new(t))));
            }
        }
        None
    }
}

impl AnthropicProvider {
    fn request(&self, body: &serde_json::Value) -> Result<serde_json::Value, crate::Error> {
        let client = reqwest::blocking::Client::new();
        let mut req = client
            .post(format!("{}/v1/messages", self.base_url))
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json");
        req = match &self.auth {
            AnthropicAuth::ApiKey(k) => req.header("x-api-key", k.as_str()),
            AnthropicAuth::Bearer(t) => req
                .header("authorization", format!("Bearer {}", t.as_str()))
                .header("anthropic-beta", "oauth-2025-04-20"),
        };
        let resp = req
            .json(body)
            .send()
            .map_err(|e| crate::Error::Provider(format!("anthropic request: {e}")))?;
        let status = resp.status();
        let payload: serde_json::Value = resp
            .json()
            .map_err(|e| crate::Error::Provider(format!("anthropic response parse: {e}")))?;
        if !status.is_success() {
            let msg = payload["error"]["message"].as_str().unwrap_or("unknown");
            return Err(crate::Error::Provider(format!("anthropic {status}: {msg}")));
        }
        Ok(payload)
    }
}

fn extract_text(payload: &serde_json::Value) -> String {
    payload["content"]
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b["type"] == "text")
                .filter_map(|b| b["text"].as_str())
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
}

impl Provider for AnthropicProvider {
    fn complete(
        &self,
        model: &str,
        system: &str,
        prompt: &str,
        images: &[ImageInput],
        max_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        let payload = self.request(&json!({
            "model": model,
            "max_tokens": max_tokens.clamp(1, 16000),
            "system": system,
            "messages": [{"role": "user", "content": anthropic_user_content(prompt, images)}],
        }))?;
        // Check stop_reason before reading content — refusals return 200
        // with empty or partial content.
        let stop_reason = payload["stop_reason"].as_str().unwrap_or("unknown");
        Ok(Completion {
            text: extract_text(&payload),
            model: payload["model"].as_str().unwrap_or(model).to_string(),
            outcome: match stop_reason {
                "end_turn" | "stop_sequence" => "ok".into(),
                other => other.into(),
            },
            input_tokens: payload["usage"]["input_tokens"].as_u64().unwrap_or(0),
            output_tokens: payload["usage"]["output_tokens"].as_u64().unwrap_or(0),
        })
    }

    /// The tool loop: model requests → host dispatches → results return →
    /// repeat until end_turn (or the iteration cap: bounded by construction).
    fn complete_with_tools(
        &self,
        model: &str,
        system: &str,
        prompt: &str,
        images: &[ImageInput],
        tools: &[crate::connector::ToolDef],
        dispatch: ToolDispatch,
        budget_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        const MAX_ITERATIONS: usize = 8;
        let base_estimate = estimate_tokens(system)
            + estimate_tokens(prompt)
            + images.len() as u64 * IMAGE_TOKEN_ESTIMATE;
        let tool_defs: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                })
            })
            .collect();
        let mut messages =
            vec![json!({"role": "user", "content": anthropic_user_content(prompt, images)})];
        let (mut in_total, mut out_total) = (0u64, 0u64);
        let mut served_model = model.to_string();

        for _ in 0..MAX_ITERATIONS {
            // Hard ceiling means INPUT counts too: estimate the next
            // call's prompt (system + the growing message history) and
            // refuse BEFORE dispatch when it alone would eat the
            // remainder — max_tokens only caps output, and a long tool
            // loop grows input every turn.
            let spent = in_total + out_total;
            let next_input = base_estimate
                + estimate_tokens(&serde_json::to_string(&messages).unwrap_or_default());
            let remaining = budget_tokens
                .saturating_sub(spent)
                .saturating_sub(next_input);
            if remaining == 0 {
                return Ok(Completion {
                    text: String::new(),
                    model: served_model,
                    outcome: "budget-exhausted".into(),
                    input_tokens: in_total,
                    output_tokens: out_total,
                });
            }
            let payload = self.request(&json!({
                "model": model,
                "max_tokens": remaining.clamp(1, 16000),
                "system": system,
                "messages": messages,
                "tools": tool_defs,
            }))?;
            in_total += payload["usage"]["input_tokens"].as_u64().unwrap_or(0);
            out_total += payload["usage"]["output_tokens"].as_u64().unwrap_or(0);
            if let Some(m) = payload["model"].as_str() {
                served_model = m.to_string();
            }
            let stop_reason = payload["stop_reason"].as_str().unwrap_or("unknown");

            if stop_reason != "tool_use" {
                return Ok(Completion {
                    text: extract_text(&payload),
                    model: served_model,
                    outcome: match stop_reason {
                        "end_turn" | "stop_sequence" => "ok".into(),
                        other => other.into(),
                    },
                    input_tokens: in_total,
                    output_tokens: out_total,
                });
            }

            // Execute every tool_use block; return ALL results in a single
            // user turn. Failures go back as is_error tool_results so the
            // model can adapt — they are not fatal to the run.
            let assistant_content = payload["content"].clone();
            let mut results = Vec::new();
            if let Some(blocks) = assistant_content.as_array() {
                for block in blocks.iter().filter(|b| b["type"] == "tool_use") {
                    let id = block["id"].as_str().unwrap_or_default();
                    let name = block["name"].as_str().unwrap_or_default();
                    let input = &block["input"];
                    match dispatch(name, input) {
                        Ok(result) => results.push(json!({
                            "type": "tool_result",
                            "tool_use_id": id,
                            "content": result,
                        })),
                        Err(e) => results.push(json!({
                            "type": "tool_result",
                            "tool_use_id": id,
                            "content": e.to_string(),
                            "is_error": true,
                        })),
                    }
                }
            }
            messages.push(json!({"role": "assistant", "content": assistant_content}));
            messages.push(json!({"role": "user", "content": results}));
        }

        Ok(Completion {
            text: String::new(),
            model: served_model,
            outcome: "max-iterations".into(),
            input_tokens: in_total,
            output_tokens: out_total,
        })
    }
}

/// Ollama local provider — the "sensitive data never leaves the host" slot.
pub struct OllamaProvider {
    pub base_url: String,
}

impl Default for OllamaProvider {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:11434".into(),
        }
    }
}

impl Provider for OllamaProvider {
    fn complete(
        &self,
        model: &str,
        system: &str,
        prompt: &str,
        _images: &[ImageInput],
        max_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        // Native ollama API here is text-only; use an openai slot with
        // base_url http://localhost:11434/v1 and a vision model for local
        // image understanding.
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("{}/api/generate", self.base_url))
            .json(&json!({
                "model": model,
                "system": system,
                "prompt": prompt,
                "stream": false,
                "options": {"num_predict": max_tokens.clamp(1, 16000)},
            }))
            .send()
            .map_err(|e| crate::Error::Provider(format!("ollama request: {e}")))?;
        let payload: serde_json::Value = resp
            .json()
            .map_err(|e| crate::Error::Provider(format!("ollama response parse: {e}")))?;
        Ok(Completion {
            text: payload["response"].as_str().unwrap_or_default().to_string(),
            model: model.to_string(),
            outcome: "ok".into(),
            input_tokens: payload["prompt_eval_count"].as_u64().unwrap_or(0),
            output_tokens: payload["eval_count"].as_u64().unwrap_or(0),
        })
    }
}

/// Deterministic mock for tests and dry runs.
pub struct MockProvider;

impl Provider for MockProvider {
    fn complete(
        &self,
        model: &str,
        _system: &str,
        prompt: &str,
        images: &[ImageInput],
        _max_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        let tag = if images.is_empty() {
            String::new()
        } else {
            format!(" [+{} images]", images.len())
        };
        Ok(Completion {
            text: format!("[mock:{model}]{tag} {prompt}"),
            model: model.to_string(),
            outcome: "ok".into(),
            input_tokens: prompt.len() as u64 / 4,
            output_tokens: 16,
        })
    }
}

/// Mock that exercises the tool path: calls each tool once (first required
/// property = the prompt), then reports the results. Tests the full
/// dispatch + logging pipeline without a network.
pub struct MockToolProvider;

impl Provider for MockToolProvider {
    fn complete(
        &self,
        model: &str,
        system: &str,
        prompt: &str,
        _images: &[ImageInput],
        max_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        MockProvider.complete(model, system, prompt, _images, max_tokens)
    }

    fn complete_with_tools(
        &self,
        model: &str,
        _system: &str,
        prompt: &str,
        _images: &[ImageInput],
        tools: &[crate::connector::ToolDef],
        dispatch: ToolDispatch,
        _budget_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        let mut reports = Vec::new();
        for tool in tools {
            let arg_name = tool.input_schema["required"][0]
                .as_str()
                .unwrap_or("input")
                .to_string();
            let args = json!({ arg_name: prompt });
            match dispatch(&tool.name, &args) {
                Ok(r) => reports.push(format!("{} -> {}", tool.name, r)),
                Err(e) => reports.push(format!("{} -> error: {}", tool.name, e)),
            }
        }
        Ok(Completion {
            text: format!("[mock-tool:{model}] {}", reports.join(" | ")),
            model: model.to_string(),
            outcome: "ok".into(),
            input_tokens: prompt.len() as u64 / 4,
            output_tokens: 32,
        })
    }
}

/// Bind a manifest inference slot to a concrete provider.
/// `credential` is the already-decrypted secret when the slot carries one
/// (JIT-decrypted by custody at call time — SPEC §5).
pub fn bind(
    provider_name: &str,
    credential: Option<Zeroizing<String>>,
    base_url: Option<String>,
) -> Result<Box<dyn Provider>, crate::Error> {
    match provider_name {
        "anthropic" => {
            let provider = match credential {
                Some(secret) => AnthropicProvider::new(AnthropicAuth::ApiKey(secret)),
                None => AnthropicProvider::from_env().ok_or_else(|| {
                    crate::Error::Provider(
                        "anthropic slot has no sealed credential and no \
                         ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN in the environment"
                            .into(),
                    )
                })?,
            };
            Ok(Box::new(provider))
        }
        "openai" | "xai" => {
            let label: &'static str = if provider_name == "xai" { "xai" } else { "openai" };
            let provider = match credential {
                Some(secret) => OpenAiCompatProvider::new(secret, base_url, label),
                None => match OpenAiCompatProvider::from_env(label, base_url.clone()) {
                    Some(p) => p,
                    // Local/self-hosted compatible endpoints (llama.cpp,
                    // LM Studio, ollama /v1) ignore auth — a custom
                    // base_url without a key gets a placeholder bearer
                    // instead of a refusal. Hosted APIs still require one.
                    None if base_url.is_some() => OpenAiCompatProvider::new(
                        Zeroizing::new("local".into()),
                        base_url,
                        label,
                    ),
                    None => {
                        return Err(crate::Error::Provider(format!(
                            "{label} slot has no sealed credential and no {} in the environment",
                            if label == "xai" { "XAI_API_KEY" } else { "OPENAI_API_KEY" }
                        )))
                    }
                },
            };
            Ok(Box::new(provider))
        }
        "ollama" => Ok(Box::new(OllamaProvider::default())),
        "mock" => Ok(Box::new(MockProvider)),
        "mock-tool" => Ok(Box::new(MockToolProvider)),
        other => Err(crate::Error::Provider(format!(
            "unknown provider '{other}' (host binds: anthropic, openai, xai, ollama, mock, mock-tool)"
        ))),
    }
}

/// OpenAI-compatible chat completions — ONE implementation for the whole
/// dialect: OpenAI itself, xAI (Grok), Groq, Together, Mistral, DeepSeek,
/// and every local server speaking it (llama.cpp, LM Studio, vLLM,
/// Ollama's /v1). Provider names `openai` and `xai` pick sensible
/// defaults; a slot's `requires.base_url` points anywhere compatible.
///
/// Tool use maps our connectors onto their function-calling format, with
/// the same budget discipline as the Anthropic loop: input is estimated
/// and counted BEFORE every call, output capped by what remains.
pub struct OpenAiCompatProvider {
    key: Zeroizing<String>,
    base_url: String,
    /// "openai" prefers max_completion_tokens (o-series reject
    /// max_tokens); the rest of the dialect still speaks max_tokens.
    strict_openai: bool,
    label: &'static str,
}

impl OpenAiCompatProvider {
    pub fn new(key: Zeroizing<String>, base_url: Option<String>, label: &'static str) -> Self {
        let (default_base, _strict) = match label {
            "xai" => ("https://api.x.ai/v1", false),
            _ => ("https://api.openai.com/v1", true),
        };
        let base_url = base_url.unwrap_or_else(|| default_base.to_string());
        Self {
            key,
            strict_openai: label == "openai" && base_url.starts_with("https://api.openai.com"),
            base_url: base_url.trim_end_matches('/').to_string(),
            label,
        }
    }

    pub fn from_env(label: &'static str, base_url: Option<String>) -> Option<Self> {
        let var = match label {
            "xai" => "XAI_API_KEY",
            _ => "OPENAI_API_KEY",
        };
        std::env::var(var)
            .ok()
            .map(|k| Self::new(Zeroizing::new(k), base_url, label))
    }

    fn request(&self, payload: &serde_json::Value) -> Result<serde_json::Value, crate::Error> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(180))
            .build()
            .map_err(|e| crate::Error::Provider(e.to_string()))?;
        let resp = client
            .post(format!("{}/chat/completions", self.base_url))
            .bearer_auth(self.key.as_str())
            .json(payload)
            .send()
            .map_err(|e| crate::Error::Provider(format!("{}: {e}", self.label)))?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .map_err(|e| crate::Error::Provider(format!("{}: body: {e}", self.label)))?;
        if !status.is_success() {
            return Err(crate::Error::Provider(format!(
                "{} refused ({status}): {}",
                self.label,
                body["error"]["message"].as_str().unwrap_or("unknown")
            )));
        }
        Ok(body)
    }

    fn payload_base(&self, model: &str, max_out: u64) -> serde_json::Value {
        let mut p = json!({"model": model});
        let capped = max_out.clamp(1, 16000);
        if self.strict_openai {
            p["max_completion_tokens"] = json!(capped);
        } else {
            p["max_tokens"] = json!(capped);
        }
        p
    }
}

fn openai_usage(body: &serde_json::Value) -> (u64, u64) {
    (
        body["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
        body["usage"]["completion_tokens"].as_u64().unwrap_or(0),
    )
}

fn openai_outcome(finish: &str) -> String {
    match finish {
        "stop" => "ok".into(),
        other => other.into(),
    }
}

impl Provider for OpenAiCompatProvider {
    fn complete(
        &self,
        model: &str,
        system: &str,
        prompt: &str,
        images: &[ImageInput],
        max_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        let mut payload = self.payload_base(model, max_tokens);
        payload["messages"] = json!([
            {"role": "system", "content": system},
            {"role": "user", "content": openai_user_content(prompt, images)},
        ]);
        let body = self.request(&payload)?;
        let (input_tokens, output_tokens) = openai_usage(&body);
        let choice = &body["choices"][0];
        Ok(Completion {
            text: choice["message"]["content"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            model: body["model"].as_str().unwrap_or(model).to_string(),
            outcome: openai_outcome(choice["finish_reason"].as_str().unwrap_or("unknown")),
            input_tokens,
            output_tokens,
        })
    }

    fn complete_with_tools(
        &self,
        model: &str,
        system: &str,
        prompt: &str,
        images: &[ImageInput],
        tools: &[crate::connector::ToolDef],
        dispatch: ToolDispatch,
        budget_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        const MAX_ITERATIONS: usize = 8;
        let tool_defs: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    },
                })
            })
            .collect();
        let base_estimate = estimate_tokens(system)
            + estimate_tokens(prompt)
            + images.len() as u64 * IMAGE_TOKEN_ESTIMATE;
        let mut messages = vec![
            json!({"role": "system", "content": system}),
            json!({"role": "user", "content": openai_user_content(prompt, images)}),
        ];
        let (mut in_total, mut out_total) = (0u64, 0u64);
        let mut served_model = model.to_string();

        for _ in 0..MAX_ITERATIONS {
            let spent = in_total + out_total;
            let next_input = base_estimate
                + estimate_tokens(&serde_json::to_string(&messages).unwrap_or_default());
            let remaining = budget_tokens
                .saturating_sub(spent)
                .saturating_sub(next_input);
            if remaining == 0 {
                return Ok(Completion {
                    text: String::new(),
                    model: served_model,
                    outcome: "budget-exhausted".into(),
                    input_tokens: in_total,
                    output_tokens: out_total,
                });
            }
            let mut payload = self.payload_base(model, remaining);
            payload["messages"] = json!(messages);
            if !tool_defs.is_empty() {
                payload["tools"] = json!(tool_defs);
            }
            let body = self.request(&payload)?;
            let (i, o) = openai_usage(&body);
            in_total += i;
            out_total += o;
            if let Some(m) = body["model"].as_str() {
                served_model = m.to_string();
            }
            let choice = &body["choices"][0];
            let finish = choice["finish_reason"].as_str().unwrap_or("unknown");
            let message = &choice["message"];
            let tool_calls = message["tool_calls"]
                .as_array()
                .cloned()
                .unwrap_or_default();

            if finish != "tool_calls" || tool_calls.is_empty() {
                return Ok(Completion {
                    text: message["content"].as_str().unwrap_or("").to_string(),
                    model: served_model,
                    outcome: openai_outcome(finish),
                    input_tokens: in_total,
                    output_tokens: out_total,
                });
            }
            // Echo the assistant turn, then answer every call — failures
            // return as tool results so the model can adapt.
            messages.push(message.clone());
            for call in &tool_calls {
                let id = call["id"].as_str().unwrap_or_default();
                let name = call["function"]["name"].as_str().unwrap_or_default();
                let args: serde_json::Value =
                    serde_json::from_str(call["function"]["arguments"].as_str().unwrap_or("{}"))
                        .unwrap_or_else(|_| json!({}));
                let content = match dispatch(name, &args) {
                    Ok(r) => r,
                    Err(e) => format!("TOOL ERROR: {e}"),
                };
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": id,
                    "content": content,
                }));
            }
        }
        Ok(Completion {
            text: String::new(),
            model: served_model,
            outcome: "max-iterations".into(),
            input_tokens: in_total,
            output_tokens: out_total,
        })
    }
}

#[cfg(test)]
mod openai_tests {
    use super::*;

    #[test]
    fn image_content_shapes_per_dialect() {
        let img = [ImageInput {
            media_type: "image/jpeg".into(),
            base64: "QUJD".into(),
        }];
        // No images → plain string content, byte-identical to the old wire shape.
        assert_eq!(anthropic_user_content("hi", &[]), json!("hi"));
        assert_eq!(openai_user_content("hi", &[]), json!("hi"));
        let a = anthropic_user_content("what is this?", &img);
        assert_eq!(a[0]["source"]["media_type"], "image/jpeg");
        assert_eq!(a[1]["text"], "what is this?");
        let o = openai_user_content("what is this?", &img);
        assert_eq!(o[0]["image_url"]["url"], "data:image/jpeg;base64,QUJD");
        assert_eq!(o[1]["text"], "what is this?");
    }

    #[test]
    fn strict_openai_uses_max_completion_tokens() {
        let p = OpenAiCompatProvider::new(Zeroizing::new("k".into()), None, "openai");
        let body = p.payload_base("gpt-5", 500);
        assert!(body.get("max_completion_tokens").is_some());
        assert!(body.get("max_tokens").is_none());
    }

    #[test]
    fn xai_and_custom_endpoints_use_max_tokens() {
        let x = OpenAiCompatProvider::new(Zeroizing::new("k".into()), None, "xai");
        assert!(x.payload_base("grok-4", 500).get("max_tokens").is_some());
        let local = OpenAiCompatProvider::new(
            Zeroizing::new("k".into()),
            Some("http://localhost:11434/v1".into()),
            "openai",
        );
        assert!(local.payload_base("qwen", 500).get("max_tokens").is_some());
    }

    #[test]
    fn usage_and_outcome_parse() {
        let body = serde_json::json!({"usage": {"prompt_tokens": 12, "completion_tokens": 34}});
        assert_eq!(openai_usage(&body), (12, 34));
        assert_eq!(openai_outcome("stop"), "ok");
        assert_eq!(openai_outcome("length"), "length");
    }
}
