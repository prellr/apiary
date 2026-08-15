//! The lease — SPEC §8 split-brain protection, §12.2 takeover modes.
//!
//! Exactly one host may run an agent's standing presence at a time. The
//! coordination primitive is nostr-native: a parameterized-replaceable
//! event (kind 34601, d-tag "apiary-lease") SIGNED BY THE AGENT'S OWN KEY
//! on the agent's log relays. Only a host holding the key can publish one,
//! so a lease is unforgeable by strangers; between legitimate hosts it is
//! a coordination record, not a lock — the takeover policy decides who
//! wins, and "contested-human" means a human does.
//!
//! Rules:
//! - CLAIM: allowed when no lease exists, the lease is expired, or we
//!   already hold it. Claiming bumps `seq`.
//! - HEARTBEAT: the running host republishes (same seq, fresh expiry)
//!   every `lease.heartbeat_secs`.
//! - YIELD: on each heartbeat the holder first reads the relay; a foreign
//!   lease with a HIGHER seq means a human authorized a takeover — the
//!   holder stops. Split-brain exposure is bounded by one heartbeat
//!   interval.
//! - TAKEOVER: publishing seq+1 over an unexpired foreign lease is a human
//!   act (the cockpit's TAKE OVER button); hosts never do it on their own.
//! - RELEASE: a graceful stop republishes with expiry now, so the next
//!   host needn't wait out the expiry window.
//!
//! One-shot runs are NOT lease-gated: the lease governs who HOSTS the
//! agent's presence, not whether an operator may run a task.

use apiary_core::custody::{AgentHandle, Custody};
use nostr::prelude::*;
use serde_json::json;
use std::path::Path;

/// Parameterized-replaceable lease event kind.
pub const LEASE_KIND: u16 = 34601;
const LEASE_D_TAG: &str = "apiary-lease";

/// This host's stable identity for lease records — random, generated once,
/// persisted at `<home>/host.id`. Not a secret; it names a machine.
pub fn host_id(home: &Path) -> String {
    let path = home.join("host.id");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    let id: String = apiary_core::identity::generate()
        .secret_key()
        .to_secret_hex()
        .chars()
        .take(16)
        .collect();
    let _ = std::fs::write(&path, &id);
    id
}

#[derive(Debug, Clone)]
pub struct LeaseView {
    pub host: String,
    pub seq: u64,
    pub expires_at: u64,
    pub created_at: u64,
}

impl LeaseView {
    pub fn expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Newest-wins ordering: higher seq first, then later created_at.
fn newer(a: &LeaseView, b: &LeaseView) -> bool {
    (a.seq, a.created_at) > (b.seq, b.created_at)
}

/// Read the agent's current lease from its relays (best view wins).
pub fn fetch(relays: &[String], agent_hex: &str) -> Option<LeaseView> {
    let filter = json!({
        "kinds": [LEASE_KIND],
        "authors": [agent_hex],
        "#d": [LEASE_D_TAG],
        "limit": 4,
    });
    let mut best: Option<LeaseView> = None;
    for relay in relays {
        let Ok(events) = crate::relay::fetch(relay, filter.clone()) else {
            continue;
        };
        for e in events {
            if e.verify().is_err() || e.pubkey.to_hex() != agent_hex {
                continue;
            }
            let Ok(body) = serde_json::from_str::<serde_json::Value>(&e.content) else {
                continue;
            };
            let view = LeaseView {
                host: body["host"].as_str().unwrap_or_default().to_string(),
                seq: body["seq"].as_u64().unwrap_or(0),
                expires_at: body["expires_at"].as_u64().unwrap_or(0),
                created_at: e.created_at.as_secs(),
            };
            if best.as_ref().is_none_or(|b| newer(&view, b)) {
                best = Some(view);
            }
        }
    }
    best
}

/// Publish a lease record. Best-effort across relays; one acceptance is a
/// claim, zero is an error (a lease nobody can read coordinates nothing).
pub fn publish(
    custody: &Custody,
    agent: &AgentHandle,
    relays: &[String],
    host: &str,
    seq: u64,
    expires_at: u64,
) -> Result<usize, crate::Error> {
    let builder = EventBuilder::new(
        Kind::Custom(LEASE_KIND),
        json!({"host": host, "seq": seq, "expires_at": expires_at}).to_string(),
    )
    .tag(Tag::custom("d", vec![LEASE_D_TAG.to_string()]));
    let event = custody.sign(agent, builder)?;
    let mut accepted = 0;
    let mut last_err = String::new();
    for relay in relays {
        match crate::relay::publish(relay, &event) {
            Ok(_) => accepted += 1,
            Err(e) => last_err = e.to_string(),
        }
    }
    if accepted == 0 {
        return Err(crate::Error::Provider(format!(
            "lease publish reached no relay ({last_err})"
        )));
    }
    Ok(accepted)
}

/// What a host holding (or wanting) the lease should do right now.
#[derive(Debug)]
pub enum Claim {
    /// We hold it (fresh publish done): heartbeat with this seq.
    Held { seq: u64 },
    /// A live foreign lease exists — do not start; a human may take over.
    Contested(LeaseView),
}

/// Try to claim (or renew) the lease for this host. Never overrides a live
/// foreign lease — that is `takeover`, a human act.
pub fn claim(
    custody: &Custody,
    agent: &AgentHandle,
    relays: &[String],
    agent_hex: &str,
    host: &str,
    expiry_secs: u64,
) -> Result<Claim, crate::Error> {
    let now = now_secs();
    let current = fetch(relays, agent_hex);
    let seq = match &current {
        Some(l) if l.host != host && !l.expired(now) => return Ok(Claim::Contested(l.clone())),
        Some(l) if l.host == host => l.seq, // renewal keeps seq
        Some(l) => l.seq + 1,               // expired foreign: supersede
        None => 1,
    };
    publish(custody, agent, relays, host, seq, now + expiry_secs)?;
    Ok(Claim::Held { seq })
}

/// Human-authorized takeover: supersede a live foreign lease with seq+1.
/// The losing host yields at its next heartbeat.
pub fn takeover(
    custody: &Custody,
    agent: &AgentHandle,
    relays: &[String],
    agent_hex: &str,
    host: &str,
    expiry_secs: u64,
) -> Result<u64, crate::Error> {
    let now = now_secs();
    let seq = fetch(relays, agent_hex).map(|l| l.seq + 1).unwrap_or(1);
    publish(custody, agent, relays, host, seq, now + expiry_secs)?;
    Ok(seq)
}

/// Graceful release: expiry now, so a successor needn't wait.
pub fn release(
    custody: &Custody,
    agent: &AgentHandle,
    relays: &[String],
    host: &str,
    seq: u64,
) -> Result<(), crate::Error> {
    publish(custody, agent, relays, host, seq, now_secs())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newest_wins_by_seq_then_time() {
        let a = LeaseView {
            host: "a".into(),
            seq: 2,
            expires_at: 10,
            created_at: 5,
        };
        let b = LeaseView {
            host: "b".into(),
            seq: 1,
            expires_at: 99,
            created_at: 50,
        };
        assert!(newer(&a, &b));
        let c = LeaseView {
            host: "c".into(),
            seq: 2,
            expires_at: 10,
            created_at: 6,
        };
        assert!(newer(&c, &a));
    }

    #[test]
    fn host_id_is_stable() {
        let dir = std::env::temp_dir().join(format!("apiary-lease-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = host_id(&dir);
        let second = host_id(&dir);
        assert_eq!(first, second);
        assert_eq!(first.len(), 16);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
