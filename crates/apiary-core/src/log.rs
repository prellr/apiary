//! The signed episodic log — SPEC §9 store 1, the agent's track record.
//!
//! Every entry is a signed nostr event: attributable, tamper-evident (each
//! entry chains to the previous via a "prev" tag), and portable. The log is
//! both proof for others and the agent's mirror (SPEC §7: self-knowledge is
//! empirical, not introspective) — so entries record enough to learn from:
//! action, acting model, cost, outcome, corrections.
//!
//! Privacy tiers (SPEC §12.3): `public` (governance events others must
//! verify), `self` (operational log, NIP-44-encrypted-to-self when published
//! to a relay), `local` (never leaves the host). Phase 1 storage is a local
//! JSONL file, so tiers are recorded but all entries stay local; relay
//! publication honors them in Phase 3.

use nostr::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::custody::{AgentHandle, Custody};

/// Custom event kind for Apiary log entries (parameterized-replaceable range
/// deliberately avoided — log entries are permanent facts).
pub const LOG_ENTRY_KIND: u16 = 4600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Plain signed event — what governance requires others to verify.
    Public,
    /// Encrypted-to-self when published; readable only by the agent.
    Self_,
    /// Never leaves the host.
    Local,
}

impl Tier {
    fn as_str(&self) -> &'static str {
        match self {
            Tier::Public => "public",
            Tier::Self_ => "self",
            Tier::Local => "local",
        }
    }
}

/// The body of a log entry — serialized as the event content.
/// Record outcomes, costs, corrections, and the acting model from day one:
/// the mirror only works if the log is honest and complete (SPEC §7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryBody {
    /// What happened: "founding.manifest", "founding.ratify", "run.task", …
    pub action: String,
    /// Which brain acted, when inference was involved ("the agent, thinking
    /// with model M, did X").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Token costs of this action, when inference was involved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<Cost>,
    /// "ok", "refusal", "error: …", "budget-refused", …
    pub outcome: String,
    /// Free-form detail (task text, result summary, manifest hash, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Cost {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Append-only, file-backed signed log. One per agent.
pub struct EpisodicLog {
    path: PathBuf,
}

impl EpisodicLog {
    pub fn open(agent_dir: &std::path::Path) -> Self {
        Self {
            path: agent_dir.join("log.jsonl"),
        }
    }

    /// Append an entry: signed by the agent (or, for ratification, by the
    /// human's handle), chained to the previous entry's event id.
    pub fn append(
        &self,
        custody: &Custody,
        signer: &AgentHandle,
        tier: Tier,
        body: &EntryBody,
    ) -> Result<Event, crate::Error> {
        let prev = self.tail(1)?.pop();
        let content = serde_json::to_string(body)?;
        let mut builder = EventBuilder::new(Kind::Custom(LOG_ENTRY_KIND), content)
            .tag(Tag::custom("tier", vec![tier.as_str().to_string()]))
            .tag(Tag::custom("action", vec![body.action.clone()]));
        if let Some(prev_event) = &prev {
            builder = builder.tag(Tag::custom("prev", vec![prev_event.id.to_hex()]));
        }
        let event = custody.sign(signer, builder)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", event.as_json())?;
        Ok(event)
    }

    /// Append an event signed elsewhere (external ratification). Foreign
    /// events carry no "prev" tag — they were signed without knowledge of
    /// this log's tip — so they act as chain ANCHORS: the chain restarts
    /// from them. Trade-off, stated plainly: deletion of entries immediately
    /// before an anchor is not tamper-evident. Anchors are rare (external
    /// ratifications), every entry is still individually signed, and the
    /// relay-published log (Phase 3) closes the gap.
    pub fn append_foreign(&self, event: &Event) -> Result<(), crate::Error> {
        event
            .verify()
            .map_err(|e| crate::Error::Manifest(format!("foreign event: bad signature: {e}")))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", event.as_json())?;
        Ok(())
    }

    /// Read all entries in order.
    pub fn read_all(&self) -> Result<Vec<Event>, crate::Error> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let reader = BufReader::new(fs::File::open(&self.path)?);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event = Event::from_json(&line)
                .map_err(|e| crate::Error::Manifest(format!("corrupt log line: {e}")))?;
            events.push(event);
        }
        Ok(events)
    }

    /// Last `n` entries, oldest first.
    pub fn tail(&self, n: usize) -> Result<Vec<Event>, crate::Error> {
        let mut all = self.read_all()?;
        let start = all.len().saturating_sub(n);
        Ok(all.split_off(start))
    }

    /// Verify every entry's signature and the prev-chain. Returns entry count.
    pub fn verify(&self) -> Result<usize, crate::Error> {
        let events = self.read_all()?;
        let mut prev_id: Option<String> = None;
        for (i, event) in events.iter().enumerate() {
            event
                .verify()
                .map_err(|e| crate::Error::Manifest(format!("entry {i}: bad signature: {e}")))?;
            let claimed_prev = event.tags.iter().find_map(|t| {
                let s = t.as_slice();
                (s.first().map(String::as_str) == Some("prev")).then(|| s.get(1).cloned())?
            });
            match (&prev_id, &claimed_prev) {
                (None, None) => {}
                (Some(expect), Some(got)) if expect == got => {}
                // No prev tag mid-log = a foreign-signed anchor (external
                // ratification): chain restarts here. See append_foreign.
                (Some(_), None) => {}
                _ => {
                    return Err(crate::Error::Manifest(format!(
                        "entry {i}: prev-chain broken (expected {prev_id:?}, got {claimed_prev:?})"
                    )))
                }
            }
            prev_id = Some(event.id.to_hex());
        }
        Ok(events.len())
    }

    pub fn parse_body(event: &Event) -> Result<EntryBody, crate::Error> {
        Ok(serde_json::from_str(&event.content)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::Custody;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("apiary-log-{}-{}", name, std::process::id()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn body(action: &str) -> EntryBody {
        EntryBody {
            action: action.into(),
            model: None,
            cost: None,
            outcome: "ok".into(),
            detail: None,
        }
    }

    #[test]
    fn append_chain_verify() {
        let dir = temp_dir("chain");
        let mut custody = Custody::new();
        let h = custody.admit(Keys::generate());
        let log = EpisodicLog::open(&dir);
        log.append(&custody, &h, Tier::Public, &body("founding.manifest")).unwrap();
        log.append(&custody, &h, Tier::Self_, &body("run.task")).unwrap();
        log.append(&custody, &h, Tier::Local, &body("run.task")).unwrap();
        assert_eq!(log.verify().unwrap(), 3);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampering_detected() {
        let dir = temp_dir("tamper");
        let mut custody = Custody::new();
        let h = custody.admit(Keys::generate());
        let log = EpisodicLog::open(&dir);
        log.append(&custody, &h, Tier::Self_, &body("a")).unwrap();
        log.append(&custody, &h, Tier::Self_, &body("b")).unwrap();
        // Remove the first line — the chain must break.
        let path = dir.join("log.jsonl");
        let contents = fs::read_to_string(&path).unwrap();
        let second_line_only: String =
            contents.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n";
        fs::write(&path, second_line_only).unwrap();
        assert!(log.verify().is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
