//! Agent-drafted amendments (SCOPE_routines, piece 5). An agent may
//! PROPOSE a change to its own constitution — "I could send you this
//! every morning, shall I?" — but never enact one: the proposal lands in
//! `manifest.proposed.yaml` beside the manifest, the cockpit shows it as
//! pending the governor's decision, and accepting it is the ordinary
//! amend-then-ratify path. Nothing new to trust: the same signature the
//! agent needs for everything else.
//!
//! Hard rule enforced here: a proposal cannot change identity or
//! governance.suspend_keys. The rest is the governor's call.

use apiary_core::manifest::{Manifest, Routine};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const PROPOSED_FILE: &str = "manifest.proposed.yaml";
pub const PROPOSAL_META: &str = "proposal.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProposalMeta {
    pub reason: String,
    pub summary: String,
    pub at: String,
    /// "routine" | "yaml"
    pub kind: String,
}

pub fn proposed_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join(PROPOSED_FILE)
}

/// Validate a candidate manifest against the current one and write it as
/// the pending proposal (replacing any earlier one — one at a time).
pub fn write_proposal(
    agent_dir: &Path,
    current: &Manifest,
    candidate: &Manifest,
    meta: ProposalMeta,
) -> Result<(), crate::Error> {
    candidate.validate()?;
    if candidate.identity.npub != current.identity.npub {
        return Err(crate::Error::Provider(
            "a proposal cannot change the agent's identity".into(),
        ));
    }
    if candidate.governance.suspend_keys != current.governance.suspend_keys {
        return Err(crate::Error::Provider(
            "a proposal cannot change who governs the agent (suspend_keys)".into(),
        ));
    }
    let yaml = candidate.to_yaml()?;
    std::fs::write(proposed_path(agent_dir), yaml)?;
    std::fs::write(
        agent_dir.join(PROPOSAL_META),
        serde_json::to_string_pretty(&meta)?,
    )?;
    Ok(())
}

pub fn read_proposal(agent_dir: &Path) -> Option<(String, ProposalMeta)> {
    let yaml = std::fs::read_to_string(proposed_path(agent_dir)).ok()?;
    let meta = std::fs::read_to_string(agent_dir.join(PROPOSAL_META))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(ProposalMeta {
            reason: String::new(),
            summary: "amendment".into(),
            at: String::new(),
            kind: "yaml".into(),
        });
    Some((yaml, meta))
}

pub fn clear_proposal(agent_dir: &Path) {
    let _ = std::fs::remove_file(proposed_path(agent_dir));
    let _ = std::fs::remove_file(agent_dir.join(PROPOSAL_META));
}

// ------------------------------------------------------------- the tools

/// `propose_routine` — structured; the safe common case.
pub struct ProposeRoutine {
    pub agent_dir: PathBuf,
    pub manifest: Manifest,
}

impl crate::connector::Connector for ProposeRoutine {
    fn def(&self) -> crate::connector::ToolDef {
        crate::connector::ToolDef {
            name: "propose_routine".into(),
            description:
                "Propose a new scheduled routine for yourself (a standing instruction the \
                          host would run on a schedule). This does NOT create it — it lands as a \
                          proposal your governor must accept and ratify. Use when a human asks for \
                          something recurring, or when you see a genuinely useful recurring task; \
                          say in `reason` why. One proposal at a time."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "short kebab-case name"},
                    "when": {"type": "string", "description": "5-field cron (Sunday=0), e.g. '0 8 * * 1-5'"},
                    "every": {"type": "string", "description": "interval instead of cron: 15m, 2h, 1d"},
                    "at": {"type": "string", "description": "one-shot: YYYY-MM-DDTHH:MM (in tz)"},
                    "tz": {"type": "string", "description": "IANA zone, e.g. America/Chicago (required with when/at)"},
                    "task": {"type": "string", "description": "the instruction to run each time"},
                    "deliver_telegram": {"type": "string", "description": "chat id to deliver the reply to (must be in your allowed_chats)"},
                    "deliver_companion": {"type": "boolean", "description": "speak the reply through the human's companion app"},
                    "as_voice": {"type": "boolean"},
                    "tokens_per_run": {"type": "integer"},
                    "reason": {"type": "string", "description": "why this routine is worth having — shown to the governor"}
                },
                "required": ["name", "task", "reason"]
            }),
        }
    }

    fn execute(
        &self,
        _custody: &apiary_core::custody::Custody,
        _agent: &apiary_core::custody::AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let s = |k: &str| {
            args[k]
                .as_str()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let name = s("name").ok_or_else(|| crate::Error::Provider("name required".into()))?;
        let name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let task = s("task").ok_or_else(|| crate::Error::Provider("task required".into()))?;
        let reason = s("reason").unwrap_or_else(|| "proposed by the agent".into());
        let mut deliver = Vec::new();
        if let Some(chat) = s("deliver_telegram") {
            deliver.push(apiary_core::manifest::Delivery {
                telegram: Some(chat),
                buzz: None,
                nostr: None,
                companion: false,
                as_voice: args["as_voice"].as_bool().unwrap_or(false),
            });
        }
        if args["deliver_companion"].as_bool().unwrap_or(false) {
            deliver.push(apiary_core::manifest::Delivery {
                telegram: None,
                buzz: None,
                nostr: None,
                companion: true,
                as_voice: args["as_voice"].as_bool().unwrap_or(false),
            });
        }
        let routine = Routine {
            name: name.clone(),
            when: s("when"),
            every: s("every"),
            at: s("at"),
            tz: s("tz"),
            task: task.clone(),
            class: "routine".into(),
            deliver,
            budget: apiary_core::manifest::RoutineBudget {
                tokens_per_run: args["tokens_per_run"].as_u64(),
            },
            catch_up: "one".into(),
            enabled: true,
        };
        // Schedule must parse (cron syntax, tz) — fail here, not at fire time.
        crate::routines::parse_schedule(&routine)?;
        let mut candidate = self.manifest.clone();
        candidate.routines.retain(|r| r.name != name);
        candidate.routines.push(routine);
        let summary = format!(
            "add routine '{name}' ({}) — {}",
            s("when")
                .or_else(|| s("every").map(|e| format!("every {e}")))
                .or_else(|| s("at").map(|a| format!("once at {a}")))
                .unwrap_or_default(),
            task.chars().take(80).collect::<String>()
        );
        write_proposal(
            &self.agent_dir,
            &self.manifest,
            &candidate,
            ProposalMeta {
                reason,
                summary: summary.clone(),
                at: chrono::Utc::now().to_rfc3339(),
                kind: "routine".into(),
            },
        )?;
        Ok(format!(
            "proposal written: {summary}. It is NOT active — your governor sees it in the cockpit and \
             decides. Tell the human it is waiting for their ratification."
        ))
    }
}

/// `propose_amendment` — the whole manifest as YAML; advanced.
pub struct ProposeAmendment {
    pub agent_dir: PathBuf,
    pub manifest: Manifest,
}

impl crate::connector::Connector for ProposeAmendment {
    fn def(&self) -> crate::connector::ToolDef {
        crate::connector::ToolDef {
            name: "propose_amendment".into(),
            description: "Propose an amendment to your own manifest (constitution) as complete YAML. \
                          Never enacted by you: it lands as a proposal the governor accepts and \
                          ratifies. Identity and suspend_keys cannot change. Prefer propose_routine \
                          for schedules. Explain the change in `reason`."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "yaml": {"type": "string", "description": "the full proposed manifest YAML"},
                    "reason": {"type": "string"}
                },
                "required": ["yaml", "reason"]
            }),
        }
    }

    fn execute(
        &self,
        _custody: &apiary_core::custody::Custody,
        _agent: &apiary_core::custody::AgentHandle,
        args: &Value,
    ) -> Result<String, crate::Error> {
        let yaml = args["yaml"]
            .as_str()
            .ok_or_else(|| crate::Error::Provider("yaml required".into()))?;
        let candidate = Manifest::from_yaml(yaml)?;
        let reason = args["reason"].as_str().unwrap_or("").to_string();
        write_proposal(
            &self.agent_dir,
            &self.manifest,
            &candidate,
            ProposalMeta {
                reason: reason.clone(),
                summary: "manifest amendment (yaml)".into(),
                at: chrono::Utc::now().to_rfc3339(),
                kind: "yaml".into(),
            },
        )?;
        Ok("proposal written — waiting for the governor to accept and ratify.".into())
    }
}
