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

pub trait Provider {
    fn complete(&self, model: &str, system: &str, prompt: &str) -> Result<Completion, crate::Error>;
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

impl Provider for AnthropicProvider {
    fn complete(&self, model: &str, system: &str, prompt: &str) -> Result<Completion, crate::Error> {
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
        let body = json!({
            "model": model,
            "max_tokens": 16000,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        });
        let resp = req
            .json(&body)
            .send()
            .map_err(|e| crate::Error::Provider(format!("anthropic request: {e}")))?;
        let status = resp.status();
        let payload: serde_json::Value = resp
            .json()
            .map_err(|e| crate::Error::Provider(format!("anthropic response parse: {e}")))?;
        if !status.is_success() {
            let msg = payload["error"]["message"].as_str().unwrap_or("unknown");
            return Err(crate::Error::Provider(format!(
                "anthropic {status}: {msg}"
            )));
        }
        // Check stop_reason before reading content — refusals return 200
        // with empty or partial content.
        let stop_reason = payload["stop_reason"].as_str().unwrap_or("unknown");
        let text: String = payload["content"]
            .as_array()
            .map(|blocks| {
                blocks
                    .iter()
                    .filter(|b| b["type"] == "text")
                    .filter_map(|b| b["text"].as_str())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        Ok(Completion {
            text,
            model: payload["model"].as_str().unwrap_or(model).to_string(),
            outcome: match stop_reason {
                "end_turn" | "stop_sequence" => "ok".into(),
                other => other.into(),
            },
            input_tokens: payload["usage"]["input_tokens"].as_u64().unwrap_or(0),
            output_tokens: payload["usage"]["output_tokens"].as_u64().unwrap_or(0),
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
    fn complete(&self, model: &str, system: &str, prompt: &str) -> Result<Completion, crate::Error> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("{}/api/generate", self.base_url))
            .json(&json!({
                "model": model,
                "system": system,
                "prompt": prompt,
                "stream": false,
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
    fn complete(&self, model: &str, _system: &str, prompt: &str) -> Result<Completion, crate::Error> {
        Ok(Completion {
            text: format!("[mock:{model}] {prompt}"),
            model: model.to_string(),
            outcome: "ok".into(),
            input_tokens: prompt.len() as u64 / 4,
            output_tokens: 16,
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
        other => Err(crate::Error::Provider(format!(
            "unknown provider '{other}' (host binds: anthropic, ollama, mock)"
        ))),
    }
}
