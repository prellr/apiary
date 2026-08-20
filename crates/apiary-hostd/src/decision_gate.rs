//! Small off-chain projection of expensive signed-state decisions.
//!
//! The signed manifest and ratification events remain the authority. This
//! gate only remembers their derived answer for the lifetime of the host.
//! A manifest/governance/review-snapshot change selects a new cache key and
//! therefore cannot inherit an earlier approval. Negative answers expire
//! quickly so an externally imported signature becomes visible promptly.

use apiary_core::{ceremony, log::EpisodicLog};
use nostr::prelude::PublicKey;
use std::{
    collections::HashMap,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};

const NEGATIVE_TTL: Duration = Duration::from_secs(2);
const PROBE_TTL: Duration = Duration::from_secs(20);

#[derive(Debug, Clone)]
pub struct AgentDecision {
    pub ratified: bool,
    pub log_entries: usize,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecisionKey {
    manifest_sha256: String,
    approval_sha256: Option<String>,
    governors: Vec<String>,
}

#[derive(Debug, Clone)]
struct CachedDecision {
    key: DecisionKey,
    decision: AgentDecision,
    evaluated_at: Instant,
}

#[derive(Debug, Clone)]
struct CachedProbeSet {
    configuration: String,
    values: Vec<serde_json::Value>,
    checked_at: Instant,
}

#[derive(Debug, Clone)]
struct CachedObservation {
    configuration: String,
    value: serde_json::Value,
    checked_at: Instant,
}

#[derive(Default)]
pub struct DecisionGate {
    decisions: Mutex<HashMap<String, CachedDecision>>,
    probes: Mutex<HashMap<String, CachedProbeSet>>,
    observations: Mutex<HashMap<String, CachedObservation>>,
}

impl DecisionGate {
    fn key(dir: &Path, raw: &str, governors: &[PublicKey]) -> DecisionKey {
        let approval_sha256 = std::fs::read_to_string(dir.join("manifest.approved.yaml"))
            .ok()
            .map(|approved| ceremony::manifest_hash(&approved));
        let mut governors = governors.iter().map(PublicKey::to_hex).collect::<Vec<_>>();
        governors.sort();
        governors.dedup();
        DecisionKey {
            manifest_sha256: ceremony::manifest_hash(raw),
            approval_sha256,
            governors,
        }
    }

    /// Derive an agent's operational admission once from signed history.
    /// Positive decisions remain valid for this configuration generation;
    /// routine/task log appends do not make governance less true. Configuration
    /// edits generate a new key and fail closed until their own ratification.
    pub fn evaluate(
        &self,
        dir: &Path,
        npub: &str,
        raw: &str,
        governors: &[PublicKey],
    ) -> AgentDecision {
        let key = Self::key(dir, raw, governors);
        if let Ok(cache) = self.decisions.lock() {
            if let Some(cached) = cache.get(npub) {
                let reusable =
                    cached.decision.ratified || cached.evaluated_at.elapsed() < NEGATIVE_TTL;
                if cached.key == key && reusable {
                    let mut decision = cached.decision.clone();
                    // Counts are display metadata, not an authority decision.
                    // Refresh them cheaply without reparsing or re-verifying.
                    decision.log_entries = EpisodicLog::open(dir)
                        .entry_count()
                        .unwrap_or(decision.log_entries);
                    return decision;
                }
            }
        }

        let events = EpisodicLog::open(dir).read_all().unwrap_or_default();
        let ratified = apiary_core::identity::parse_npub(npub)
            .ok()
            .and_then(|agent| ceremony::is_ratified_events(&events, raw, &agent, governors).ok())
            .unwrap_or(false);
        let decision = AgentDecision {
            ratified,
            log_entries: events.len(),
            manifest_sha256: key.manifest_sha256.clone(),
        };
        if let Ok(mut cache) = self.decisions.lock() {
            cache.insert(
                npub.to_string(),
                CachedDecision {
                    key,
                    decision: decision.clone(),
                    evaluated_at: Instant::now(),
                },
            );
        }
        decision
    }

    pub fn invalidate(&self, npub: &str) {
        if let Ok(mut cache) = self.decisions.lock() {
            cache.remove(npub);
        }
        if let Ok(mut cache) = self.probes.lock() {
            cache.remove(npub);
        }
    }

    /// Health checks are observations, not governance. Keep their most
    /// recent answer briefly instead of shelling out or touching every local
    /// provider whenever a UI/MCP client refreshes.
    pub fn inference_probes(
        &self,
        npub: &str,
        configuration: &str,
        refresh: impl FnOnce() -> Vec<serde_json::Value>,
    ) -> Vec<serde_json::Value> {
        if let Ok(cache) = self.probes.lock() {
            if let Some(cached) = cache.get(npub) {
                if cached.configuration == configuration && cached.checked_at.elapsed() < PROBE_TTL
                {
                    return cached.values.clone();
                }
            }
        }
        let values = refresh();
        if let Ok(mut cache) = self.probes.lock() {
            cache.insert(
                npub.to_string(),
                CachedProbeSet {
                    configuration: configuration.to_string(),
                    values: values.clone(),
                    checked_at: Instant::now(),
                },
            );
        }
        values
    }

    pub fn observation(
        &self,
        key: &str,
        configuration: &str,
        ttl: Duration,
        refresh: impl FnOnce() -> serde_json::Value,
    ) -> serde_json::Value {
        if let Ok(cache) = self.observations.lock() {
            if let Some(cached) = cache.get(key) {
                if cached.configuration == configuration && cached.checked_at.elapsed() < ttl {
                    return cached.value.clone();
                }
            }
        }
        let value = refresh();
        if let Ok(mut cache) = self.observations.lock() {
            cache.insert(
                key.to_string(),
                CachedObservation {
                    configuration: configuration.to_string(),
                    value: value.clone(),
                    checked_at: Instant::now(),
                },
            );
        }
        value
    }

    pub fn clear(&self) {
        if let Ok(mut cache) = self.decisions.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.probes.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.observations.lock() {
            cache.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiary_core::{
        custody::Custody,
        log::{EntryBody, Tier},
    };
    use nostr::prelude::Keys;

    #[test]
    fn signed_decision_is_reused_but_a_manifest_change_fails_closed() {
        let dir = std::env::temp_dir().join(format!(
            "apiary-decision-gate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = "manifest_version: 1\n";
        let mut custody = Custody::new();
        let agent_keys = Keys::generate();
        let agent_npub = apiary_core::identity::to_npub(&agent_keys.public_key()).unwrap();
        let agent = custody.admit(agent_keys);
        let governor_keys = Keys::generate();
        let governor_pk = governor_keys.public_key();
        let governor = custody.admit(governor_keys);
        let log = EpisodicLog::open(&dir);
        ceremony::sign_manifest(&custody, &agent, &log, raw).unwrap();
        ceremony::ratify(&custody, &governor, &log, &agent_npub, raw).unwrap();
        std::fs::write(dir.join("manifest.approved.yaml"), raw).unwrap();

        let gate = DecisionGate::default();
        let first = gate.evaluate(&dir, &agent_npub, raw, &[governor_pk]);
        assert!(first.ratified);
        assert_eq!(first.log_entries, 2);

        log.append(
            &custody,
            &agent,
            Tier::Self_,
            &EntryBody {
                action: "run.task".into(),
                model: None,
                cost: None,
                harness: None,
                outcome: "ok".into(),
                detail: None,
            },
        )
        .unwrap();
        let projected = gate.evaluate(&dir, &agent_npub, raw, &[governor_pk]);
        assert!(projected.ratified);
        assert_eq!(projected.log_entries, 3);

        let amended = gate.evaluate(
            &dir,
            &agent_npub,
            "manifest_version: 1\nname: changed\n",
            &[governor_pk],
        );
        assert!(!amended.ratified);
        std::fs::remove_dir_all(dir).ok();
    }
}
