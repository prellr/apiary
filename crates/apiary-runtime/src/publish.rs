//! Log publication — SPEC §12.3 made real. The signed log becomes portable
//! and third-party-verifiable by living on relays, with privacy tiers
//! enforced at the publication boundary:
//!
//! - `public` — published as-is: founding, ratifications, anything
//!   governance requires others to verify. Idempotent (same event id).
//! - `self`   — wrapped: a kind-4601 event, signed by the agent, whose
//!   content is the NIP-44 encryption (to the agent's own key) of the
//!   original entry. Portable and durable, readable only by the agent.
//! - `local`  — never leaves the host. Not even encrypted.
//!
//! Wrapper events get fresh ids, so publication state is tracked locally
//! (published.json, 0600) to keep republication idempotent.

use apiary_core::custody::{AgentHandle, Custody};
use apiary_core::log::{EpisodicLog, LOG_ENTRY_KIND};
use nostr::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Wrapped (encrypted-to-self) log entry kind.
pub const WRAPPED_KIND: u16 = 4601;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Published {
    /// original event id (hex) → published event id (same for public,
    /// wrapper id for self-tier).
    entries: BTreeMap<String, String>,
}

pub struct PublishReport {
    pub published_public: usize,
    pub published_wrapped: usize,
    pub skipped_local: usize,
    pub already_published: usize,
    pub relay_results: Vec<String>,
}

fn tier_of(event: &Event) -> &str {
    event
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.first().map(String::as_str) == Some("tier")).then(|| s.get(1))?
        })
        .map(String::as_str)
        .unwrap_or("local") // untagged entries fail closed: never published
}

fn published_path(agent_dir: &Path) -> std::path::PathBuf {
    agent_dir.join("published.json")
}

fn load_published(agent_dir: &Path) -> Published {
    std::fs::read_to_string(published_path(agent_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn store_published(agent_dir: &Path, p: &Published) -> Result<(), crate::Error> {
    let path = published_path(agent_dir);
    std::fs::write(&path, serde_json::to_string_pretty(p)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Build the wrapper event for a self-tier entry (no publication — pure).
pub fn wrap_self_entry(
    custody: &Custody,
    agent: &AgentHandle,
    entry: &Event,
) -> Result<Event, crate::Error> {
    let sealed = custody.seal(agent, &entry.as_json())?;
    let builder = EventBuilder::new(Kind::Custom(WRAPPED_KIND), sealed.nip44)
        .tag(Tag::custom("wrapped", vec![entry.id.to_hex()]))
        .tag(Tag::custom("tier", vec!["self".to_string()]));
    Ok(custody.sign(agent, builder)?)
}

/// Unwrap a kind-4601 event fetched from a relay back into the original
/// signed log entry (verifies the inner signature too).
pub fn unwrap_self_entry(
    custody: &Custody,
    agent: &AgentHandle,
    wrapper: &Event,
) -> Result<Event, crate::Error> {
    let blob = apiary_core::manifest::EncryptedBlob {
        nip44: wrapper.content.clone(),
    };
    let plain = custody.open(agent, &blob)?;
    let inner = Event::from_json(plain.as_str())
        .map_err(|e| crate::Error::Provider(format!("wrapped entry parse: {e}")))?;
    inner
        .verify()
        .map_err(|e| crate::Error::Provider(format!("wrapped entry signature: {e}")))?;
    Ok(inner)
}

/// Publish the log to the given relays, honoring tiers. Idempotent across
/// invocations via the local publication record.
pub fn publish_log(
    agent_dir: &Path,
    custody: &Custody,
    agent: &AgentHandle,
    relays: &[String],
) -> Result<PublishReport, crate::Error> {
    if relays.is_empty() {
        return Err(crate::Error::Provider(
            "no relays configured (manifest memory.log_relays)".into(),
        ));
    }
    let log = EpisodicLog::open(agent_dir);
    let mut published = load_published(agent_dir);
    let mut report = PublishReport {
        published_public: 0,
        published_wrapped: 0,
        skipped_local: 0,
        already_published: 0,
        relay_results: Vec::new(),
    };
    for entry in log.read_all()? {
        let original_id = entry.id.to_hex();
        if published.entries.contains_key(&original_id) {
            report.already_published += 1;
            continue;
        }
        let outbound = match tier_of(&entry) {
            "public" => entry.clone(),
            "self" => wrap_self_entry(custody, agent, &entry)?,
            _ => {
                report.skipped_local += 1;
                continue;
            }
        };
        let mut accepted_somewhere = false;
        for relay in relays {
            match crate::relay::publish(relay, &outbound) {
                Ok(msg) => {
                    accepted_somewhere = true;
                    report.relay_results.push(format!("{relay}: {msg}"));
                }
                Err(e) => report.relay_results.push(format!("{relay}: FAILED {e}")),
            }
        }
        if accepted_somewhere {
            if outbound.kind == Kind::Custom(LOG_ENTRY_KIND) {
                report.published_public += 1;
            } else {
                report.published_wrapped += 1;
            }
            published.entries.insert(original_id, outbound.id.to_hex());
        }
    }
    store_published(agent_dir, &published)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiary_core::log::{EntryBody, Tier};

    #[test]
    fn wrap_roundtrip_and_stranger_cannot_read() {
        let dir = std::env::temp_dir().join(format!("apiary-wrap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut custody = Custody::new();
        let agent = custody.admit(Keys::generate());
        let log = EpisodicLog::open(&dir);
        let entry = log
            .append(
                &custody,
                &agent,
                Tier::Self_,
                &EntryBody {
                    action: "run.task".into(),
                    model: Some("m".into()),
                    cost: None,
                    harness: None,
                    outcome: "ok".into(),
                    detail: Some(serde_json::json!({"task": "private business"})),
                },
            )
            .unwrap();

        let wrapper = wrap_self_entry(&custody, &agent, &entry).unwrap();
        // The wrapper leaks nothing: the private text is not in the content.
        assert!(!wrapper.content.contains("private business"));
        assert_eq!(wrapper.kind, Kind::Custom(WRAPPED_KIND));
        wrapper.verify().unwrap();

        // The agent can unwrap and recover the exact signed original…
        let inner = unwrap_self_entry(&custody, &agent, &wrapper).unwrap();
        assert_eq!(inner.id, entry.id);
        // …a stranger cannot.
        let stranger = custody.admit(Keys::generate());
        assert!(unwrap_self_entry(&custody, &stranger, &wrapper).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn untagged_entries_fail_closed() {
        // An event with no tier tag must be treated as local (never leaves).
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(LOG_ENTRY_KIND), "{}")
            .finalize(&keys)
            .unwrap();
        assert_eq!(tier_of(&event), "local");
    }
}
