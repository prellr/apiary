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
            harness: None,
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
    let agent_pk = crate::identity::parse_npub(agent_npub)?;
    log.append_with_tags(
        custody,
        human,
        Tier::Public,
        &EntryBody {
            action: "founding.ratify".into(),
            model: None,
            cost: None,
            harness: None,
            outcome: "ratified".into(),
            detail: Some(json!({
                "agent": agent_npub,
                "manifest_sha256": manifest_hash(manifest_yaml),
            })),
        },
        vec![Tag::public_key(agent_pk)],
    )
}

/// Build the ratification event UNSIGNED, for external signing — the path
/// for humans whose master key rightly never enters Apiary custody. The
/// caller exports this JSON, signs it with their own nostr tooling
/// (extension, client, NIP-46 signer), and imports the signed event back.
pub fn ratification_unsigned(
    ratifier: PublicKey,
    agent_npub: &str,
    manifest_yaml: &str,
) -> Result<UnsignedEvent, crate::Error> {
    let body = EntryBody {
        action: "founding.ratify".into(),
        model: None,
        cost: None,
        harness: None,
        outcome: "ratified".into(),
        detail: Some(json!({
            "agent": agent_npub,
            "manifest_sha256": manifest_hash(manifest_yaml),
        })),
    };
    let content = serde_json::to_string(&body)?;
    let agent_pk = crate::identity::parse_npub(agent_npub)?;
    let builder = EventBuilder::new(Kind::Custom(crate::log::LOG_ENTRY_KIND), content)
        .tag(Tag::custom("tier", vec!["public".to_string()]))
        .tag(Tag::custom("action", vec!["founding.ratify".to_string()]))
        .tag(Tag::public_key(agent_pk));
    Ok(builder.finalize_unsigned(ratifier))
}

/// Verify and append an externally-signed ratification event. Checks: valid
/// signature, signer is a listed suspend key, action and manifest hash
/// match. The event is re-chained into the log (the prev-chain is a local
/// storage property; the signature covers identity and content).
pub fn import_ratification(
    log: &EpisodicLog,
    event: &Event,
    manifest_yaml: &str,
    suspend_keys: &[PublicKey],
) -> Result<(), crate::Error> {
    event
        .verify()
        .map_err(|e| crate::Error::Manifest(format!("bad signature on ratification: {e}")))?;
    if !suspend_keys.contains(&event.pubkey) {
        return Err(crate::Error::Manifest(
            "ratification signer is not a listed suspend key".into(),
        ));
    }
    let body = EpisodicLog::parse_body(event)?;
    if body.action != "founding.ratify" {
        return Err(crate::Error::Manifest("event is not a ratification".into()));
    }
    let want = manifest_hash(manifest_yaml);
    let got = body
        .detail
        .as_ref()
        .and_then(|d| d.get("manifest_sha256"))
        .and_then(|v| v.as_str());
    if got != Some(want.as_str()) {
        return Err(crate::Error::Manifest(format!(
            "ratification hash mismatch: manifest is {want}, event ratifies {got:?} — \
             the manifest changed since export; re-export and re-sign"
        )));
    }
    log.append_foreign(event)
}

/// True when the log holds a COMPLETE, VERIFIED founding for this exact
/// manifest: an agent-signed `founding.manifest` AND a suspend-key-signed
/// `founding.ratify` naming this agent, both with valid signatures, the
/// right kind, and the current manifest hash. Nothing here trusts a log
/// entry's claims without checking its cryptography — a same-host process
/// can write to the log file, but it cannot forge either signature.
pub fn is_ratified(
    log: &EpisodicLog,
    manifest_yaml: &str,
    agent: &PublicKey,
    suspend_keys: &[PublicKey],
) -> Result<bool, crate::Error> {
    let events = log.read_all()?;
    is_ratified_events(&events, manifest_yaml, agent, suspend_keys)
}

/// Evaluate ratification from an already-loaded snapshot. Host admission can
/// parse the signed history once, derive several off-chain views from it, and
/// avoid turning each view into a separate full-log scan.
pub fn is_ratified_events(
    events: &[Event],
    manifest_yaml: &str,
    agent: &PublicKey,
    suspend_keys: &[PublicKey],
) -> Result<bool, crate::Error> {
    let want = manifest_hash(manifest_yaml);
    let agent_npub = crate::identity::to_npub(agent)?;
    let hash_matches = |body: &EntryBody| {
        body.detail
            .as_ref()
            .and_then(|d| d.get("manifest_sha256"))
            .and_then(|v| v.as_str())
            == Some(want.as_str())
    };
    let mut agent_signed = false;
    let mut human_ratified = false;
    for event in events {
        // Cryptographic checks first: signature and kind. Unverifiable
        // entries are ignored, never trusted.
        if event.kind != Kind::Custom(crate::log::LOG_ENTRY_KIND) || event.verify().is_err() {
            continue;
        }
        let Ok(body) = EpisodicLog::parse_body(event) else {
            continue;
        };
        match body.action.as_str() {
            "founding.manifest" => {
                if event.pubkey == *agent && hash_matches(&body) {
                    agent_signed = true;
                }
            }
            "founding.ratify" => {
                let names_agent = body
                    .detail
                    .as_ref()
                    .and_then(|d| d.get("agent"))
                    .and_then(|v| v.as_str())
                    == Some(agent_npub.as_str());
                if suspend_keys.contains(&event.pubkey) && names_agent && hash_matches(&body) {
                    human_ratified = true;
                }
            }
            _ => {}
        }
    }
    Ok(agent_signed && human_ratified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::Custody;

    #[test]
    fn external_ratification_roundtrip() {
        let dir = std::env::temp_dir().join(format!("apiary-extrat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = EpisodicLog::open(&dir);

        // The human's key lives "outside" — we simulate their signer here.
        let human = Keys::generate();
        let manifest_yaml = "manifest_version: 1\n";

        // The agent signs its manifest through custody; the human signs
        // externally. BOTH are required for is_ratified.
        let mut custody = Custody::new();
        let agent_keys = Keys::generate();
        let agent_pk = agent_keys.public_key();
        let agent = custody.admit(agent_keys);
        let agent_npub = crate::identity::to_npub(&agent_pk).unwrap();
        sign_manifest(&custody, &agent, &log, manifest_yaml).unwrap();
        // Human signature alone (not yet imported) → not ratified.
        assert!(!is_ratified(&log, manifest_yaml, &agent_pk, &[human.public_key()]).unwrap());

        // Export unsigned → sign externally → import.
        let unsigned =
            ratification_unsigned(human.public_key(), &agent_npub, manifest_yaml).unwrap();
        let signed = human.sign_event(unsigned).unwrap();
        import_ratification(&log, &signed, manifest_yaml, &[human.public_key()]).unwrap();
        assert!(is_ratified(&log, manifest_yaml, &agent_pk, &[human.public_key()]).unwrap());

        // Wrong hash, wrong signer, wrong agent: all rejected.
        assert!(import_ratification(
            &log,
            &signed,
            "different: manifest\n",
            &[human.public_key()]
        )
        .is_err());
        let stranger = Keys::generate();
        assert!(
            import_ratification(&log, &signed, manifest_yaml, &[stranger.public_key()]).is_err()
        );
        assert!(!is_ratified(
            &log,
            manifest_yaml,
            &stranger.public_key(),
            &[human.public_key()]
        )
        .unwrap());

        // Chain still verifies with the foreign anchor, also after a
        // custody-signed entry follows it.
        log.append(
            &custody,
            &agent,
            crate::log::Tier::Self_,
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
        assert_eq!(log.verify().unwrap(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }
}
