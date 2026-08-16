//! Native portability — SPEC §1's four-part claim made mechanical.
//!
//! An Apiary agent IS manifest + key + signed log; a host is somewhere it
//! runs. The export bundle is exactly those parts in one versioned JSON
//! file, and import verifies all of them before an agent dir exists:
//!
//! - the NIP-49 key blob travels STILL LOCKED (the passphrase moves out of
//!   band, human to human) and must decrypt to the bundle's npub;
//! - the manifest must name that same npub;
//! - every log event must carry a valid signature, the chain must verify,
//!   and the current manifest must be ratified — an import cannot smuggle
//!   in an unratified constitution or a doctored history.
//!
//! Deliberately NOT exported: the active flag, spend ledger, semantic
//! index, and host id — those are operational state of a host, not
//! substance of the agent. An imported agent arrives INACTIVE with a fresh
//! ledger; activating it walks the same lease gate as anything else, so
//! migration is: export → import → deactivate old → activate new, with
//! `contested-human` refereeing any overlap.

use crate::{ceremony, keystore::Keystore, log::EpisodicLog, manifest::Manifest};
use nostr::prelude::*;
use serde_json::{json, Value};
use std::path::Path;

pub const EXPORT_VERSION: u64 = 1;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Package an agent directory into the export bundle, key copied verbatim
/// (still locked with the keystore passphrase).
pub fn export(agent_dir: &Path, npub: &str) -> Result<Value, crate::Error> {
    export_with_passphrase(agent_dir, npub, None)
}

/// Package with the key RE-ENCRYPTED under a dedicated export passphrase —
/// the handoff secret. This is how an agent is given to someone else: your
/// keystore passphrase never travels, the recipient never learns it, and
/// the export passphrase is disposable after one import (their host
/// re-encrypts under their own passphrase on arrival).
///
/// Note on governance: handing over the key hands over the ability to act
/// AS the agent — but not to amend its constitution. Amendments still need
/// ratification by a listed suspend key, so a proper transfer amends
/// `governance.suspend_keys` to include the recipient (ratified by YOU)
/// before export.
pub fn export_with_passphrase(
    agent_dir: &Path,
    npub: &str,
    reencrypt: Option<(&str, &str)>, // (keystore passphrase, export passphrase)
) -> Result<Value, crate::Error> {
    let read = |name: &str| -> Result<String, crate::Error> {
        std::fs::read_to_string(agent_dir.join(name))
            .map_err(|e| crate::Error::Keystore(format!("export: cannot read {name}: {e}")))
    };
    let manifest_yaml = read("manifest.yaml")?;
    let mut key_ncryptsec = read("key.ncryptsec")?.trim().to_string();
    if let Some((keystore_pass, export_pass)) = reencrypt {
        if export_pass.is_empty() {
            return Err(crate::Error::Keystore("export passphrase is empty".into()));
        }
        let enc = EncryptedSecretKey::from_bech32(&key_ncryptsec)
            .map_err(|e| crate::Error::Keystore(format!("parse ncryptsec: {e}")))?;
        let sk = enc.decrypt(keystore_pass).map_err(|e| {
            crate::Error::Keystore(format!("keystore passphrase does not open the key: {e}"))
        })?;
        key_ncryptsec = EncryptedSecretKey::new(&sk, export_pass, 16, KeySecurity::Medium)
            .map_err(|e| crate::Error::Keystore(format!("nip49 re-encrypt: {e}")))?
            .to_bech32()
            .map_err(|e| crate::Error::Keystore(format!("bech32: {e}")))?;
    }
    let name = std::fs::read_to_string(agent_dir.join("name"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let log_events: Vec<Value> = EpisodicLog::open(agent_dir)
        .read_all()?
        .iter()
        .map(|e| serde_json::from_str(&e.as_json()).unwrap_or(Value::Null))
        .collect();
    let published: Option<Value> = std::fs::read_to_string(agent_dir.join("published.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    // ALL of the agent's memory travels: the signed log above and the
    // semantic index here — recall included, nothing to rebuild, no
    // dependency on the destination having the same embedding model.
    let index_jsonl = std::fs::read_to_string(agent_dir.join("index.jsonl")).ok();
    Ok(json!({
        "apiary_export": EXPORT_VERSION,
        "exported_at": now_secs(),
        "npub": npub,
        "name": name,
        "manifest_yaml": manifest_yaml,
        "key_ncryptsec": key_ncryptsec,
        "log": log_events,
        "published": published,
        "index_jsonl": index_jsonl,
    }))
}

#[derive(Debug)]
pub struct ImportReport {
    pub npub: String,
    pub name: String,
    pub log_entries: usize,
    pub ratified: bool,
    /// Semantic-index rows accepted (verified against the signed log).
    pub index_rows: usize,
    /// Index rows dropped: unknown event id or text disagreeing with the
    /// signed entry — an unsigned index never overrides the log.
    pub index_dropped: usize,
    /// False only for gap-tolerant imports (relay recovery without the
    /// local tier).
    pub chain_intact: bool,
}

/// Verify a bundle end to end and materialize the agent directory. The
/// passphrase must open the traveling key — proof the importer is the
/// rightful recipient, not just someone holding the file.
pub fn import(
    ks: &Keystore,
    bundle: &Value,
    bundle_passphrase: &str,
    keystore_passphrase: &str,
) -> Result<ImportReport, crate::Error> {
    import_with_options(ks, bundle, bundle_passphrase, keystore_passphrase, true)
}

/// `strict_chain: false` is for RELAY RECOVERY: local-tier entries never
/// left the machine, so a recovered log legitimately has gaps. Signatures
/// still verify per event; `chain_intact` reports what survived.
pub fn import_with_options(
    ks: &Keystore,
    bundle: &Value,
    bundle_passphrase: &str,
    keystore_passphrase: &str,
    strict_chain: bool,
) -> Result<ImportReport, crate::Error> {
    let fail = |msg: String| crate::Error::Keystore(format!("import: {msg}"));
    if bundle.get("apiary_export").and_then(Value::as_u64) != Some(EXPORT_VERSION) {
        return Err(fail(format!(
            "not an apiary export v{EXPORT_VERSION} bundle"
        )));
    }
    let field = |k: &str| -> Result<String, crate::Error> {
        bundle
            .get(k)
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| fail(format!("bundle missing '{k}'")))
    };
    let npub = field("npub")?;
    let manifest_yaml = field("manifest_yaml")?;
    let key_ncryptsec = field("key_ncryptsec")?;
    let name = bundle
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    // 1. The key must decrypt with the provided passphrase and be the npub.
    let enc = EncryptedSecretKey::from_bech32(key_ncryptsec.trim())
        .map_err(|e| fail(format!("key blob is not valid ncryptsec: {e}")))?;
    let secret = enc.decrypt(bundle_passphrase).map_err(|e| {
        fail(format!(
            "bundle passphrase does not open the traveling key: {e}"
        ))
    })?;
    let keys = Keys::new(secret);
    let derived = crate::identity::to_npub(&keys.public_key())?;
    if derived != npub {
        return Err(fail(format!(
            "key decrypts to {derived}, bundle claims {npub}"
        )));
    }

    // 2. The constitution must be the agent's own.
    let manifest = Manifest::from_yaml(&manifest_yaml)
        .map_err(|e| fail(format!("manifest does not parse: {e}")))?;
    let identity_ok = crate::identity::parse_npub(&manifest.identity.npub)
        .ok()
        .and_then(|pk| crate::identity::to_npub(&pk).ok())
        .is_some_and(|n| n == npub);
    if !identity_ok {
        return Err(fail("manifest identity.npub does not match the key".into()));
    }

    // 3. Every log event must be genuinely signed.
    let events = bundle
        .get("log")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut lines = Vec::with_capacity(events.len());
    for (i, raw) in events.iter().enumerate() {
        let event = Event::from_json(raw.to_string())
            .map_err(|e| fail(format!("log[{i}] is not a nostr event: {e}")))?;
        event
            .verify()
            .map_err(|_| fail(format!("log[{i}] has an invalid signature")))?;
        lines.push(event.as_json());
    }

    // 4. Materialize — refusing to clobber an existing agent.
    let dir = ks.agent_dir(&npub);
    if dir.join("manifest.yaml").exists() || dir.join("key.ncryptsec").exists() {
        return Err(fail(format!(
            "agent {npub} already exists on this host — refusing to overwrite"
        )));
    }
    // The key is stored RE-ENCRYPTED under THIS keystore's passphrase —
    // the whole keystore stays openable with one passphrase, and the
    // export passphrase dies with the handoff.
    ks.store(&keys, keystore_passphrase)?;
    let write = |name: &str, content: &str| -> Result<(), crate::Error> {
        std::fs::write(dir.join(name), content).map_err(|e| fail(format!("write {name}: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    };
    write("manifest.yaml", &manifest_yaml)?;
    if !name.is_empty() {
        write("name", &name)?;
    }
    write("log.jsonl", &(lines.join("\n") + "\n"))?;
    // Semantic index: unsigned derived data, so every row is checked
    // against the signed log — the event id must exist and the text must
    // equal what that entry derives. Disagreeing rows are dropped, not
    // trusted; a missing index just rebuilds on the next run.
    let mut index_rows = 0usize;
    let mut index_dropped = 0usize;
    if let Some(index_raw) = bundle.get("index_jsonl").and_then(Value::as_str) {
        let mut expected: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for line in &lines {
            if let Ok(event) = Event::from_json(line.as_str()) {
                if let Ok(body) = serde_json::from_str::<crate::log::EntryBody>(&event.content) {
                    expected.insert(event.id.to_hex(), body.index_text());
                }
            }
        }
        let mut kept = Vec::new();
        for line in index_raw.lines().filter(|l| !l.trim().is_empty()) {
            // Vault rows derive from HOST-LOCAL files (memory.vaults) —
            // they neither travel nor count as tampering; the destination
            // re-indexes its own copy of the vaults.
            if serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|r| r.get("event_id").and_then(|v| v.as_str()).map(String::from))
                .is_some_and(|id| id.starts_with("vault:"))
            {
                continue;
            }
            let ok = serde_json::from_str::<Value>(line).ok().is_some_and(|row| {
                row.get("event_id")
                    .and_then(Value::as_str)
                    .and_then(|id| expected.get(id))
                    .is_some_and(|want| {
                        row.get("text").and_then(Value::as_str) == Some(want.as_str())
                    })
            });
            if ok {
                kept.push(line.to_string());
                index_rows += 1;
            } else {
                index_dropped += 1;
            }
        }
        if !kept.is_empty() {
            write("index.jsonl", &(kept.join("\n") + "\n"))?;
        }
    }
    if let Some(published) = bundle.get("published").filter(|v| !v.is_null()) {
        write("published.json", &published.to_string())?;
    }

    // 5. Chain + ratification verified in place; roll back on failure
    // (unless the caller expects gaps — relay recovery).
    let log = EpisodicLog::open(&dir);
    let (entries, chain_intact) = match log.verify() {
        Ok(n) => (n, true),
        Err(e) if strict_chain => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(fail(format!("log chain does not verify: {e}")));
        }
        Err(_) => (lines.len(), false),
    };
    let suspend: Vec<PublicKey> = manifest
        .governance
        .suspend_keys
        .iter()
        .filter_map(|k| crate::identity::parse_npub(k).ok())
        .collect();
    let agent_pk = crate::identity::parse_npub(&npub)?;
    let ratified =
        ceremony::is_ratified(&log, &manifest_yaml, &agent_pk, &suspend).unwrap_or(false);
    // The stated invariant holds at the border: an unratified constitution
    // does not get installed — no key lands, no state lands. (Runtime
    // gates would refuse it anyway; the keystore should never hold it.)
    if !ratified {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(fail(
            "bundle's manifest is not ratified by its listed suspend keys — refused and rolled back"
                .into(),
        ));
    }

    Ok(ImportReport {
        npub,
        name,
        log_entries: entries,
        ratified,
        index_rows,
        index_dropped,
        chain_intact,
    })
}

// ---------------------------------------------------------------- sealed

/// Sealed handoff event kind (see docs/SCOPE_sealed-handoffs.md).
pub const HANDOFF_KIND: u16 = 4602;

/// Seal an agent to a recipient's key: one kind-4602 nostr event, AUTHORED
/// BY THE AGENT'S OWN KEY (the agent signs its own handoff), p-tagged to
/// the recipient, content = NIP-44 ciphertext of the bundle. Inside the
/// ciphertext the traveling key is locked under a one-time machine
/// passphrase no human ever sees. No shared secret in flight; any
/// truncation or omission breaks the envelope signature.
pub fn seal(
    agent_dir: &Path,
    npub: &str,
    keystore_passphrase: &str,
    recipient: &PublicKey,
) -> Result<Value, crate::Error> {
    let fail = |msg: String| crate::Error::Keystore(format!("seal: {msg}"));
    // One-time inner passphrase: 32 random bytes of hex, never displayed.
    let otp = crate::identity::generate().secret_key().to_secret_hex();
    let mut bundle = export_with_passphrase(agent_dir, npub, Some((keystore_passphrase, &otp)))?;
    bundle["key_passphrase"] = json!(otp);
    // The agent's key signs the envelope and performs the ECDH.
    let ncryptsec = std::fs::read_to_string(agent_dir.join("key.ncryptsec"))
        .map_err(|e| fail(e.to_string()))?;
    let enc = EncryptedSecretKey::from_bech32(ncryptsec.trim())
        .map_err(|e| fail(format!("parse ncryptsec: {e}")))?;
    let keys = Keys::new(
        enc.decrypt(keystore_passphrase)
            .map_err(|e| fail(format!("keystore passphrase does not open the key: {e}")))?,
    );
    let ciphertext = nip44::encrypt(
        keys.secret_key(),
        recipient,
        bundle.to_string(),
        nip44::Version::V2,
    )
    .map_err(|e| fail(format!("nip44 encrypt: {e}")))?;
    let event = EventBuilder::new(Kind::Custom(HANDOFF_KIND), ciphertext)
        .tag(Tag::public_key(*recipient))
        .finalize(&keys)
        .map_err(|e| fail(format!("sign envelope: {e}")))?;
    serde_json::from_str(&event.as_json()).map_err(|e| fail(e.to_string()))
}

/// Is this JSON a sealed handoff envelope (vs a plain bundle)?
pub fn is_sealed(v: &Value) -> bool {
    v.get("kind").and_then(Value::as_u64) == Some(HANDOFF_KIND as u64) && v.get("sig").is_some()
}

/// Open a sealed envelope with the recipient's keys. Verifies the envelope
/// signature, the kind, that the p tag names this recipient, and the
/// self-consistency rule: the envelope author must be the very npub inside
/// the decrypted bundle — the agent being handed over signed the handoff.
pub fn open_sealed(envelope: &Value, recipient: &Keys) -> Result<Value, crate::Error> {
    let fail = |msg: String| crate::Error::Keystore(format!("sealed import: {msg}"));
    let event = Event::from_json(envelope.to_string())
        .map_err(|e| fail(format!("not a nostr event: {e}")))?;
    if event.kind != Kind::Custom(HANDOFF_KIND) {
        return Err(fail(format!(
            "kind {} is not a handoff",
            event.kind.as_u16()
        )));
    }
    event
        .verify()
        .map_err(|_| fail("envelope signature does not verify".into()))?;
    let addressed_to = event.tags.iter().find_map(|t| {
        let s = t.as_slice();
        (s.first().map(String::as_str) == Some("p")).then(|| s.get(1).cloned())?
    });
    if addressed_to.as_deref() != Some(recipient.public_key().to_hex().as_str()) {
        return Err(fail(format!(
            "envelope is addressed to {}, not to this key",
            addressed_to.unwrap_or_else(|| "nobody".into())
        )));
    }
    let plain = nip44::decrypt(recipient.secret_key(), &event.pubkey, &event.content)
        .map_err(|e| fail(format!("decrypt failed — wrong recipient key? ({e})")))?;
    let bundle: Value =
        serde_json::from_str(&plain).map_err(|e| fail(format!("inner bundle: {e}")))?;
    let inner_npub = bundle
        .get("npub")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("inner bundle has no npub".into()))?;
    let inner_pk = crate::identity::parse_npub(inner_npub)?;
    if inner_pk != event.pubkey {
        return Err(fail(
            "envelope author is not the agent inside — self-consistency failed".into(),
        ));
    }
    Ok(bundle)
}

/// One import entry for every form: plain bundle (optionally
/// handoff-locked) or sealed envelope, auto-detected. For sealed input the
/// recipient key is resolved from the keystore by the envelope's p tag
/// (`as_npub` overrides), and the inner one-time key passphrase is
/// consumed automatically.
pub fn import_any(
    ks: &Keystore,
    value: &Value,
    bundle_passphrase: Option<&str>,
    keystore_passphrase: &str,
    as_npub: Option<&str>,
) -> Result<ImportReport, crate::Error> {
    let fail = |msg: String| crate::Error::Keystore(format!("import: {msg}"));
    if !is_sealed(value) {
        return import_with_options(
            ks,
            value,
            bundle_passphrase.unwrap_or(keystore_passphrase),
            keystore_passphrase,
            true,
        );
    }
    let addressed_to = value
        .get("tags")
        .and_then(Value::as_array)
        .and_then(|tags| {
            tags.iter().find_map(|t| {
                let a = t.as_array()?;
                (a.first()?.as_str()? == "p").then(|| a.get(1)?.as_str().map(String::from))?
            })
        })
        .ok_or_else(|| fail("envelope has no recipient p tag".into()))?;
    let recipient_npub = match as_npub {
        Some(n) => {
            let pk = crate::identity::parse_npub(n)?;
            if pk.to_hex() != addressed_to {
                return Err(fail(format!(
                    "--as key does not match the envelope's recipient ({addressed_to})"
                )));
            }
            crate::identity::to_npub(&pk)?
        }
        None => {
            let want = crate::identity::to_npub(
                &PublicKey::from_hex(&addressed_to)
                    .map_err(|e| fail(format!("envelope p tag is not a public key: {e}")))?,
            )?;
            if !ks.list()?.contains(&want) {
                return Err(fail(format!(
                    "the envelope is sealed to {want}, and this keystore holds no such key — \
                     import that key first, or check you are the intended recipient"
                )));
            }
            want
        }
    };
    let recipient_keys = ks.load(&recipient_npub, keystore_passphrase)?;
    let bundle = open_sealed(value, &recipient_keys)?;
    let otp = bundle
        .get("key_passphrase")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("sealed bundle carries no inner key passphrase".into()))?
        .to_string();
    import_with_options(ks, &bundle, &otp, keystore_passphrase, true)
}

#[cfg(test)]
mod sealed_tests {
    use super::*;

    fn fixture(dir: &Path, pass: &str) -> (Keystore, String) {
        let ks = Keystore::open(dir).unwrap();
        let keys = crate::identity::generate();
        let npub = crate::identity::to_npub(&keys.public_key()).unwrap();
        ks.store(&keys, pass).unwrap();
        // Suspension authority never rests with the agent's own key — and
        // imports refuse unratified bundles, so the fixture runs the full
        // founding ceremony.
        let governor_keys = crate::identity::generate();
        let governor = crate::identity::to_npub(&governor_keys.public_key()).unwrap();
        let adir = ks.agent_dir(&npub);
        let manifest_yaml = format!(
            "manifest_version: 1\nidentity:\n  npub: {npub}\nmemory:\n  log: local\n  \
             index: local\ngovernance:\n  suspend_keys:\n  - {governor}\n"
        );
        std::fs::write(adir.join("manifest.yaml"), &manifest_yaml).unwrap();
        std::fs::write(adir.join("name"), "fixture").unwrap();
        let mut custody = crate::custody::Custody::new();
        let agent_handle = custody.admit(keys);
        let governor_handle = custody.admit(governor_keys);
        let log = EpisodicLog::open(&adir);
        ceremony::sign_manifest(&custody, &agent_handle, &log, &manifest_yaml).unwrap();
        ceremony::ratify(&custody, &governor_handle, &log, &npub, &manifest_yaml).unwrap();
        (ks, npub)
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("apiary-sealed-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn unratified_bundles_refuse_and_roll_back() {
        let home = tmp("unrat");
        let ks = Keystore::open(&home).unwrap();
        let keys = crate::identity::generate();
        let npub = crate::identity::to_npub(&keys.public_key()).unwrap();
        ks.store(&keys, "p").unwrap();
        let governor = crate::identity::to_npub(&crate::identity::generate().public_key()).unwrap();
        let adir = ks.agent_dir(&npub);
        std::fs::write(
            adir.join("manifest.yaml"),
            format!(
                "manifest_version: 1\nidentity:\n  npub: {npub}\nmemory:\n  log: local\n  \
                 index: local\ngovernance:\n  suspend_keys:\n  - {governor}\n"
            ),
        )
        .unwrap();
        // No ceremony: export succeeds (reads files), import must refuse.
        let bundle = export(&adir, &npub).unwrap();
        let rx = tmp("unrat-rx");
        let rx_ks = Keystore::open(&rx).unwrap();
        let err = import(&rx_ks, &bundle, "p", "p").unwrap_err().to_string();
        assert!(err.contains("not ratified"), "{err}");
        assert!(
            !rx_ks.agent_dir(&npub).join("manifest.yaml").exists(),
            "rolled back"
        );
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&rx);
    }

    #[test]
    fn sealed_round_trip_and_refusals() {
        let sender_home = tmp("sender");
        let (ks, npub) = fixture(&sender_home, "sender-pass");
        // Bisect guard: the fixture's ceremony must verify in place.
        {
            let adir = ks.agent_dir(&npub);
            let raw = std::fs::read_to_string(adir.join("manifest.yaml")).unwrap();
            let m = Manifest::from_yaml(&raw).unwrap();
            let suspend: Vec<PublicKey> = m
                .governance
                .suspend_keys
                .iter()
                .filter_map(|k| crate::identity::parse_npub(k).ok())
                .collect();
            let pk = crate::identity::parse_npub(&npub).unwrap();
            let log = EpisodicLog::open(&adir);
            assert!(
                ceremony::is_ratified(&log, &raw, &pk, &suspend).unwrap(),
                "fixture ceremony did not ratify in place"
            );
        }
        let recipient = crate::identity::generate();
        let envelope = seal(
            &ks.agent_dir(&npub),
            &npub,
            "sender-pass",
            &recipient.public_key(),
        )
        .unwrap();
        assert!(is_sealed(&envelope));

        // Right key opens; self-consistency holds.
        let bundle = open_sealed(&envelope, &recipient).unwrap();
        assert_eq!(bundle["npub"].as_str().unwrap(), npub);
        assert!(bundle["key_passphrase"].as_str().is_some());

        // Wrong recipient key: refused at the p-tag gate.
        let stranger = crate::identity::generate();
        assert!(open_sealed(&envelope, &stranger).is_err());

        // Tampered ciphertext: refused.
        let mut tampered = envelope.clone();
        let mut ct = tampered["content"].as_str().unwrap().to_string();
        ct.replace_range(10..11, if &ct[10..11] == "A" { "B" } else { "A" });
        tampered["content"] = json!(ct);
        assert!(
            Event::from_json(tampered.to_string()).is_err() || {
                // signature breaks before decrypt is even attempted
                open_sealed(&tampered, &recipient).is_err()
            }
        );

        // Full import into the recipient's own keystore, THEIR passphrase.
        let rx_home = tmp("rx");
        let rx_ks = Keystore::open(&rx_home).unwrap();
        let rx_npub = crate::identity::to_npub(&recipient.public_key()).unwrap();
        rx_ks.store(&recipient, "rx-pass").unwrap();
        let report = import_any(&rx_ks, &envelope, None, "rx-pass", None).unwrap();
        assert_eq!(report.npub, npub);
        // The stored key opens under the RECIPIENT's passphrase now.
        assert!(rx_ks.load(&npub, "rx-pass").is_ok());
        // Plain no-flag export still round-trips (nothing is required).
        let _ = rx_npub;
        let plain = export(&rx_ks.agent_dir(&npub), &npub);
        assert!(plain.is_ok());

        let _ = std::fs::remove_dir_all(&sender_home);
        let _ = std::fs::remove_dir_all(&rx_home);
    }
}
