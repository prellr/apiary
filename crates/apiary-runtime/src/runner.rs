//! The one-shot agent loop — Phase 1's "a principal exists."
//!
//! Order matters and encodes the spec: spend floor first (§8), route (§7),
//! JIT-decrypt the slot credential (§5), hydrate memory (§9 — the loop, not
//! a pipe), infer, then write the signed log entry recording model, cost,
//! and outcome (§9) and fold spend back into the ledger. Process-kill is the
//! Phase 1 stop mechanism: every run is a discrete, bounded action.

use apiary_core::custody::{AgentHandle, Custody};
use apiary_core::log::{Cost, EntryBody, EpisodicLog, Tier};
use apiary_core::manifest::Manifest;
use serde_json::json;
use std::path::Path;

use crate::inference::{bind, Completion};
use crate::routing::TaskContext;
use crate::spend::{tokens_per_day, SpendLedger};

pub struct RunOutcome {
    pub completion: Completion,
    pub slot: String,
    pub log_event_id: String,
}

/// How many recent log entries hydrate the working set.
const MEMORY_TAIL: usize = 12;

pub fn run_task(
    manifest: &Manifest,
    agent_dir: &Path,
    custody: &Custody,
    agent: &AgentHandle,
    task: &str,
    ctx: &TaskContext,
) -> Result<RunOutcome, crate::Error> {
    let log = EpisodicLog::open(agent_dir);
    let ledger = SpendLedger::open(agent_dir);

    // 1. Spend floor — refuse before any inference, and log the refusal:
    //    a budget denial is part of the track record too.
    let cap = tokens_per_day(&manifest.governance.budgets);
    if let Err(e) = ledger.check(cap) {
        log.append(
            custody,
            agent,
            Tier::Self_,
            &EntryBody {
                action: "run.task".into(),
                model: None,
                cost: None,
                harness: None,
                outcome: "budget-refused".into(),
                detail: Some(json!({ "task": task })),
            },
        )?;
        return Err(e);
    }

    // 2. Route — floors clamp, host decides, model is never consulted.
    let slot_name = crate::routing::resolve(manifest, ctx)?;
    let slot = manifest
        .inference
        .iter()
        .find(|s| s.name == slot_name)
        .ok_or_else(|| crate::Error::Routing(format!("slot '{slot_name}' not in pool")))?;
    let model = slot.model.clone().unwrap_or_else(|| "claude-opus-5".into());

    // 3. JIT-decrypt the slot credential, if the agent owns one.
    let credential = match &slot.credential {
        Some(blob) => Some(custody.open(agent, blob)?),
        None => None,
    };
    let provider = bind(&slot.provider, credential)?;

    // 4. Hydrate the working set from the episodic log (memory is a loop).
    let mut memory_lines = Vec::new();
    for event in log.tail(MEMORY_TAIL)? {
        if let Ok(body) = EpisodicLog::parse_body(&event) {
            memory_lines.push(format!(
                "- [{}] {} → {}{}",
                event.created_at,
                body.action,
                body.outcome,
                body.detail
                    .as_ref()
                    .and_then(|d| d.get("task"))
                    .and_then(|t| t.as_str())
                    .map(|t| format!(" (task: {t})"))
                    .unwrap_or_default(),
            ));
        }
    }
    // The agent reads its own constitution: connectors it holds, budgets
    // that bind it, who can suspend it. (Its first live run asked for
    // exactly this — the log showed THAT it signed, not WHAT.)
    let connector_names: Vec<&str> =
        manifest.connectors.iter().map(|c| c.kind.as_str()).collect();
    let system = format!(
        "You are an Apiary agent. Your identity is the nostr key {npub}. \
         You are a durable principal: your memory below persists across runs \
         and everything you do is signed into your permanent log.\n\n\
         Your ratified manifest (your constitution):\n\
         - Connectors you hold: {connectors}\n\
         - Budgets binding you: {budgets}\n\
         - Humans who can suspend you: {suspend}\n\n\
         Recent log entries (your episodic memory):\n{memory}",
        npub = manifest.identity.npub,
        connectors = if connector_names.is_empty() {
            "none — you cannot act on the world this run, only think and answer".to_string()
        } else {
            connector_names.join(", ")
        },
        budgets = serde_json::to_string(&manifest.governance.budgets).unwrap_or_default(),
        suspend = manifest.governance.suspend_keys.join(", "),
        memory = if memory_lines.is_empty() {
            "(none yet — this is your first recorded action)".to_string()
        } else {
            memory_lines.join("\n")
        },
    );

    // 5. Bind connectors (default-deny: an empty manifest list means no
    //    capabilities exist) and infer. Every dispatch is logged BEFORE the
    //    result returns to the model — the track record sees each action.
    let connectors = crate::connector::bind_connectors(manifest)?;
    let completion = if connectors.is_empty() {
        provider.complete(&model, &system, task)?
    } else {
        let tool_defs: Vec<crate::connector::ToolDef> =
            connectors.iter().map(|c| c.def()).collect();
        let mut dispatch = |name: &str, args: &serde_json::Value| {
            let connector = connectors
                .iter()
                .find(|c| c.def().name == name)
                .ok_or_else(|| {
                    crate::Error::Provider(format!("model requested unknown tool '{name}'"))
                })?;
            let result = connector.execute(custody, agent, args);
            log.append(
                custody,
                agent,
                Tier::Self_,
                &EntryBody {
                    action: "tool.call".into(),
                    model: Some(model.clone()),
                    cost: None,
                    harness: Some("native".into()),
                    outcome: match &result {
                        Ok(_) => "ok".into(),
                        Err(e) => format!("error: {e}"),
                    },
                    detail: Some(json!({ "tool": name, "args": args })),
                },
            )?;
            result
        };
        provider.complete_with_tools(&model, &system, task, &tool_defs, &mut dispatch)?
    };

    // 6. Record: signed log entry with acting model, cost, outcome — then
    //    fold spend back into the ledger.
    let event = log.append(
        custody,
        agent,
        Tier::Self_,
        &EntryBody {
            action: "run.task".into(),
            model: Some(completion.model.clone()),
            cost: Some(Cost {
                input_tokens: completion.input_tokens,
                output_tokens: completion.output_tokens,
            }),
            harness: Some("native".into()),
            outcome: completion.outcome.clone(),
            detail: Some(json!({
                "task": task,
                "slot": slot_name,
                "response_chars": completion.text.len(),
            })),
        },
    )?;
    ledger.record(completion.input_tokens, completion.output_tokens)?;

    Ok(RunOutcome {
        completion,
        slot: slot_name,
        log_event_id: event.id.to_hex(),
    })
}

pub struct AcpRunOutcome {
    pub text: String,
    pub stop_reason: String,
    pub tool_calls: Vec<(String, String)>,
    pub permissions: Vec<(String, String)>,
    pub log_event_id: String,
}

/// Run a task through a FOREIGN harness (ACP sidecar) under the same
/// governance shell as the native loop: budget floor first, permission
/// requests decided by host policy, the whole session signed into the log
/// with harness attribution. The loop is rented; the shell is ours.
#[allow(clippy::too_many_arguments)]
pub fn run_acp_task(
    manifest: &Manifest,
    agent_dir: &Path,
    custody: &Custody,
    agent: &AgentHandle,
    task: &str,
    command: &str,
    args: &[String],
    allow_permissions: bool,
) -> Result<AcpRunOutcome, crate::Error> {
    let log = EpisodicLog::open(agent_dir);
    let ledger = SpendLedger::open(agent_dir);
    let harness = format!("acp:{command}");

    // Budget floor still gates entry. ACP runtimes don't report token usage
    // on the wire, so spend inside the session is unmetered — recorded as
    // such rather than pretended away. (Metering lands with provider-side
    // accounting in the daemon.)
    let cap = tokens_per_day(&manifest.governance.budgets);
    if let Err(e) = ledger.check(cap) {
        log.append(custody, agent, Tier::Self_, &EntryBody {
            action: "run.task".into(),
            model: None,
            cost: None,
            harness: Some(harness),
            outcome: "budget-refused".into(),
            detail: Some(json!({ "task": task })),
        })?;
        return Err(e);
    }

    let mode = if allow_permissions {
        crate::acp::PermissionMode::Allow
    } else {
        crate::acp::PermissionMode::Deny
    };
    let result = crate::acp::run_acp_prompt(
        command,
        args,
        agent_dir,
        task,
        mode,
        std::time::Duration::from_secs(300),
    )?;

    let event = log.append(custody, agent, Tier::Self_, &EntryBody {
        action: "run.task".into(),
        model: None, // the foreign harness picks its own model
        cost: None,
        harness: Some(harness),
        outcome: result.stop_reason.clone(),
        detail: Some(json!({
            "task": task,
            "response_chars": result.text.len(),
            "tool_calls": result.tool_calls,
            "permission_decisions": result.permissions,
            "permission_mode": if allow_permissions { "allow" } else { "deny" },
            "tokens_unmetered": true,
        })),
    })?;

    Ok(AcpRunOutcome {
        text: result.text,
        stop_reason: result.stop_reason,
        tool_calls: result.tool_calls,
        permissions: result.permissions,
        log_event_id: event.id.to_hex(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiary_core::identity;
    use nostr::prelude::*;

    fn setup() -> (Manifest, std::path::PathBuf, Custody, AgentHandle) {
        let mut custody = Custody::new();
        let keys = Keys::generate();
        let npub = identity::to_npub(&keys.public_key()).unwrap();
        let handle = custody.admit(keys);
        let human = identity::to_npub(&Keys::generate().public_key()).unwrap();
        let manifest = Manifest::from_yaml(&format!(
            r#"
manifest_version: 1
identity:
  npub: {npub}
inference:
  - name: brain
    provider: mock
    model: test-model
routing:
  default: brain
connectors: []
memory:
  log: local
governance:
  suspend_keys:
    - {human}
  budgets:
    tokens_per_day: 100
"#
        ))
        .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "apiary-run-{}-{}",
            npub.chars().rev().take(8).collect::<String>(),
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        (manifest, dir, custody, handle)
    }

    #[test]
    fn run_logs_and_spends_then_budget_refuses() {
        let (manifest, dir, custody, handle) = setup();
        let ctx = TaskContext::default();

        let out = run_task(&manifest, &dir, &custody, &handle, "say hello", &ctx).unwrap();
        assert!(out.completion.text.contains("say hello"));
        assert_eq!(out.slot, "brain");

        // Log has one signed, verifiable entry.
        let log = EpisodicLog::open(&dir);
        assert_eq!(log.verify().unwrap(), 1);

        // Burn through the 100-token/day budget (mock spends ~16+ per run).
        let mut refused = false;
        for _ in 0..12 {
            if run_task(&manifest, &dir, &custody, &handle, "again", &ctx).is_err() {
                refused = true;
                break;
            }
        }
        assert!(refused, "budget floor never triggered");
        // The refusal itself is in the log, and the chain still verifies.
        assert!(log.verify().unwrap() >= 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tool_dispatch_executes_and_logs() {
        let (mut manifest, dir, custody, handle) = setup();
        manifest.inference[0].provider = "mock-tool".into();
        manifest.connectors = vec![apiary_core::manifest::Connector {
            kind: "mock-echo".into(),
            credential: None,
            caps: Default::default(),
        }];
        let out = run_task(&manifest, &dir, &custody, &handle, "ping", &TaskContext::default())
            .unwrap();
        // The mock-tool provider dispatched mock_echo with the prompt.
        assert!(out.completion.text.contains("mock_echo -> echo: ping"), "{}", out.completion.text);
        // The log holds the tool.call entry AND the run.task entry, chained.
        let log = EpisodicLog::open(&dir);
        let entries = log.tail(10).unwrap();
        let actions: Vec<String> = entries
            .iter()
            .map(|e| EpisodicLog::parse_body(e).unwrap().action)
            .collect();
        assert_eq!(actions, vec!["tool.call", "run.task"]);
        assert_eq!(log.verify().unwrap(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn memory_hydrates_from_log() {
        let (manifest, dir, custody, handle) = setup();
        let ctx = TaskContext::default();
        run_task(&manifest, &dir, &custody, &handle, "first task", &ctx).unwrap();
        // The mock echoes the prompt only, so verify hydration via the log:
        // second run must see a non-empty tail (asserted indirectly — the
        // system prompt is built from the same tail() call verified here).
        let log = EpisodicLog::open(&dir);
        assert_eq!(log.tail(12).unwrap().len(), 1);
        run_task(&manifest, &dir, &custody, &handle, "second task", &ctx).unwrap();
        assert_eq!(log.tail(12).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }
}
