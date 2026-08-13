//! The founding ceremony — SPEC §7/§11 Phase 1: constitution, then amendments.
//!
//! Founding produces the log's first two entries: the agent signs its own
//! manifest hash ("this is who I am and what I may do"), then a human
//! suspend-key holder ratifies the same hash. Both signatures are ordinary
//! log entries, so the ceremony is auditable forever with `log verify`.
//! The founding manifest is explicitly a hypothesis — founding is the moment
//! of maximum ignorance; amendments revise it with evidence.

use nostr::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::custody::{AgentHandle, Custody};
use crate::log::{EntryBody, EpisodicLog, Tier};

/// Canonical hash of the manifest text as ratified.
pub fn manifest_hash(manifest_yaml: &str) -> String {
    let digest = Sha256::digest(manifest_yaml.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Step 1: the agent signs its manifest into the log (public tier — third
/// parties must be able to verify what was founded).
pub fn sign_manifest(
    custody: &Custody,
    agent: &AgentHandle,
    log: &EpisodicLog,
    manifest_yaml: &str,
) -> Result<Event, crate::Error> {
    log.append(
        custody,
        agent,
        Tier::Public,
        &EntryBody {
            action: "founding.manifest".into(),
            model: None,
            cost: None,
            outcome: "signed".into(),
            detail: Some(json!({ "manifest_sha256": manifest_hash(manifest_yaml) })),
        },
    )
}

/// Step 2: a human suspend-key holder ratifies. The ratifier's handle must
/// belong to a key listed in `governance.suspend_keys` — checked by the
/// caller against the manifest before invoking (the CLI does this).
pub fn ratify(
    custody: &Custody,
    human: &AgentHandle,
    log: &EpisodicLog,
    agent_npub: &str,
    manifest_yaml: &str,
) -> Result<Event, crate::Error> {
    log.append(
        custody,
        human,
        Tier::Public,
        &EntryBody {
            action: "founding.ratify".into(),
            model: None,
            cost: None,
            outcome: "ratified".into(),
            detail: Some(json!({
                "agent": agent_npub,
                "manifest_sha256": manifest_hash(manifest_yaml),
            })),
        },
    )
}

/// True when the log contains a ratification whose hash matches this
/// manifest, signed by one of the given suspend keys.
pub fn is_ratified(
    log: &EpisodicLog,
    manifest_yaml: &str,
    suspend_keys: &[PublicKey],
) -> Result<bool, crate::Error> {
    let want = manifest_hash(manifest_yaml);
    for event in log.read_all()? {
        if !suspend_keys.contains(&event.pubkey) {
            continue;
        }
        let body = EpisodicLog::parse_body(&event)?;
        if body.action != "founding.ratify" {
            continue;
        }
        if body
            .detail
            .as_ref()
            .and_then(|d| d.get("manifest_sha256"))
            .and_then(|v| v.as_str())
            == Some(want.as_str())
        {
            return Ok(true);
        }
    }
    Ok(false)
}
