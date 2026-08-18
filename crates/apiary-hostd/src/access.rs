//! Persistent host-manager allowlist. Public identities only: a manager's
//! private key stays in their signer. CLI `--admin` keys are bootstrap entries;
//! stored managers survive daemon restarts and can be managed from the cockpit.

use nostr::prelude::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const VERSION: u32 = 1;
const FILE_NAME: &str = "host-managers.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredFile {
    version: u32,
    managers: Vec<StoredManager>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredManager {
    name: String,
    npub: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ManagerView {
    pub name: String,
    pub npub: String,
    pub source: &'static str,
    pub removable: bool,
}

pub struct ManagerRegistry {
    path: PathBuf,
    bootstrap: Vec<PublicKey>,
    stored: Vec<(PublicKey, StoredManager)>,
}

impl ManagerRegistry {
    pub fn load(home: &Path, bootstrap: Vec<PublicKey>) -> Result<Self, String> {
        let path = home.join(FILE_NAME);
        let file = match std::fs::read_to_string(&path) {
            Ok(raw) => {
                let file: StoredFile = serde_json::from_str(&raw)
                    .map_err(|error| format!("{} is invalid: {error}", path.display()))?;
                if file.version != VERSION {
                    return Err(format!(
                        "{} has unsupported version {} (expected {VERSION})",
                        path.display(),
                        file.version
                    ));
                }
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => StoredFile {
                version: VERSION,
                managers: Vec::new(),
            },
            Err(error) => return Err(format!("could not read {}: {error}", path.display())),
        };
        let mut seen = HashSet::new();
        let mut stored = Vec::new();
        for mut manager in file.managers {
            validate_name(&manager.name)?;
            let key = apiary_core::identity::parse_npub(&manager.npub)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            manager.npub = apiary_core::identity::to_npub(&key).map_err(|e| e.to_string())?;
            if seen.insert(key) {
                stored.push((key, manager));
            }
        }
        Ok(Self {
            path,
            bootstrap: dedupe(bootstrap),
            stored,
        })
    }

    #[cfg(test)]
    pub fn in_memory(bootstrap: Vec<PublicKey>) -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "apiary-manager-test-{}-{}.json",
                std::process::id(),
                unique_suffix()
            )),
            bootstrap: dedupe(bootstrap),
            stored: Vec::new(),
        }
    }

    pub fn contains(&self, key: &PublicKey) -> bool {
        self.bootstrap.contains(key) || self.stored.iter().any(|(stored, _)| stored == key)
    }

    pub fn is_empty(&self) -> bool {
        self.bootstrap.is_empty() && self.stored.is_empty()
    }

    pub fn len(&self) -> usize {
        self.views().len()
    }

    pub fn views(&self) -> Vec<ManagerView> {
        let mut views = Vec::new();
        for key in &self.bootstrap {
            let npub = apiary_core::identity::to_npub(key).unwrap_or_else(|_| key.to_hex());
            let stored_name = self
                .stored
                .iter()
                .find(|(stored, _)| stored == key)
                .map(|(_, manager)| manager.name.clone());
            views.push(ManagerView {
                name: stored_name.unwrap_or_else(|| short_name(&npub)),
                npub,
                source: "startup",
                removable: false,
            });
        }
        for (key, manager) in &self.stored {
            if self.bootstrap.contains(key) {
                continue;
            }
            views.push(ManagerView {
                name: manager.name.clone(),
                npub: manager.npub.clone(),
                source: "stored",
                removable: true,
            });
        }
        views.sort_by_key(|manager| manager.name.to_lowercase());
        views
    }

    pub fn upsert(&mut self, key: PublicKey, name: String) -> Result<(), std::io::Error> {
        let npub = apiary_core::identity::to_npub(&key)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let mut candidate = self.stored.clone();
        if let Some((_, manager)) = candidate.iter_mut().find(|(stored, _)| stored == &key) {
            manager.name = name;
            manager.npub = npub;
        } else {
            candidate.push((key, StoredManager { name, npub }));
        }
        self.save(&candidate)?;
        self.stored = candidate;
        Ok(())
    }

    pub fn remove(&mut self, key: &PublicKey) -> Result<RemoveOutcome, std::io::Error> {
        if self.bootstrap.contains(key) {
            return Ok(RemoveOutcome::StartupManager);
        }
        if !self.stored.iter().any(|(stored, _)| stored == key) {
            return Ok(RemoveOutcome::NotFound);
        }
        let candidate: Vec<_> = self
            .stored
            .iter()
            .filter(|(stored, _)| stored != key)
            .cloned()
            .collect();
        if self.bootstrap.is_empty() && candidate.is_empty() {
            return Ok(RemoveOutcome::LastManager);
        }
        self.save(&candidate)?;
        self.stored = candidate;
        Ok(RemoveOutcome::Removed)
    }

    fn save(&self, managers: &[(PublicKey, StoredManager)]) -> Result<(), std::io::Error> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_vec_pretty(&StoredFile {
            version: VERSION,
            managers: managers
                .iter()
                .map(|(_, manager)| manager.clone())
                .collect(),
        })?;
        let tmp = self.path.with_extension(format!("tmp-{}", unique_suffix()));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&body)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RemoveOutcome {
    Removed,
    NotFound,
    StartupManager,
    LastManager,
}

pub fn validate_name(name: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 60 {
        Err("manager name must be 1–60 characters".into())
    } else {
        Ok(())
    }
}

fn dedupe(keys: Vec<PublicKey>) -> Vec<PublicKey> {
    let mut seen = HashSet::new();
    keys.into_iter().filter(|key| seen.insert(*key)).collect()
}

fn short_name(npub: &str) -> String {
    format!(
        "{}…{}",
        &npub[..npub.len().min(12)],
        &npub[npub.len().saturating_sub(6)..]
    )
}

fn unique_suffix() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_managers_survive_reload_and_last_manager_is_protected() {
        let home = std::env::temp_dir().join(format!(
            "apiary-access-test-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        let key = apiary_core::identity::generate().public_key();
        let mut registry = ManagerRegistry::load(&home, Vec::new()).unwrap();
        registry.upsert(key, "Alice".into()).unwrap();
        let mut reloaded = ManagerRegistry::load(&home, Vec::new()).unwrap();
        assert!(reloaded.contains(&key));
        assert_eq!(reloaded.views()[0].name, "Alice");
        assert_eq!(reloaded.remove(&key).unwrap(), RemoveOutcome::LastManager);
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn bootstrap_manager_cannot_be_removed_remotely() {
        let key = apiary_core::identity::generate().public_key();
        let mut registry = ManagerRegistry::in_memory(vec![key]);
        assert_eq!(
            registry.remove(&key).unwrap(),
            RemoveOutcome::StartupManager
        );
    }
}
