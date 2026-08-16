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
        max_tokens: u64,
    ) -> Result<Completion, crate::Error>;

    /// Multi-turn tool loop under a cumulative token budget: each iteration
    /// is clamped to what remains, and the loop stops (outcome
    /// "budget-exhausted") rather than overrunning. Providers without tool
    /// support fall back to a plain completion and flag it.
    fn complete_with_tools(
        &self,
        model: &str,
        system: &str,
        prompt: &str,
        tools: &[crate::connector::ToolDef],
        _dispatch: ToolDispatch,
        budget_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        let mut c = self.complete(model, system, prompt, budget_tokens)?;
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
        max_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        let payload = self.request(&json!({
            "model": model,
            "max_tokens": max_tokens.clamp(1, 16000),
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
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
        tools: &[crate::connector::ToolDef],
        dispatch: ToolDispatch,
        budget_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        const MAX_ITERATIONS: usize = 8;
        let base_estimate = estimate_tokens(system) + estimate_tokens(prompt);
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
        let mut messages = vec![json!({"role": "user", "content": prompt})];
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
        max_tokens: u64,
    ) -> Result<Completion, crate::Error> {
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
        _max_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        Ok(Completion {
            text: format!("[mock:{model}] {prompt}"),
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
        max_tokens: u64,
    ) -> Result<Completion, crate::Error> {
        MockProvider.complete(model, system, prompt, max_tokens)
    }

    fn complete_with_tools(
        &self,
        model: &str,
        _system: &str,
        prompt: &str,
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
        "ollama" => Ok(Box::new(OllamaProvider::default())),
        "mock" => Ok(Box::new(MockProvider)),
        "mock-tool" => Ok(Box::new(MockToolProvider)),
        other => Err(crate::Error::Provider(format!(
            "unknown provider '{other}' (host binds: anthropic, ollama, mock, mock-tool)"
        ))),
    }
}
