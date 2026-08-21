//! Dev keystore — NIP-49 encrypted agent keys at rest.
//!
//! Phase 0 explicitly ships *dev* custody: keys live on the host, encrypted
//! with a passphrase (NIP-49 / ncryptsec). The production path is a NIP-46
//! remote signer (SPEC §3); this module is the key *source*, so swapping it
//! out later does not disturb the `Custody` API.
//!
//! Layout: `<state_dir>/agents/<npub>/key.ncryptsec` (0600) next to
//! `manifest.yaml`. State dirs are never committed (.gitignore).

use nostr::nips::nip49::{EncryptedSecretKey, KeySecurity};
use nostr::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Keystore {
    state_dir: PathBuf,
    root: PathBuf,
}

impl Keystore {
    /// Open (creating if needed) a keystore rooted at `<state_dir>/agents`.
    pub fn open(state_dir: &Path) -> Result<Self, crate::Error> {
        let root = state_dir.join("agents");
        fs::create_dir_all(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // State dirs are private to the user: 0700 all the way down.
            let _ = fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
        }
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            root,
        })
    }

    fn workspace_verifier_path(&self) -> PathBuf {
        self.state_dir.join("workspace.ncryptsec")
    }

    fn write_workspace_verifier(&self, passphrase: &str) -> Result<(), crate::Error> {
        let keys = Keys::generate();
        let enc =
            EncryptedSecretKey::new(keys.secret_key(), passphrase, 16, KeySecurity::Medium)
                .map_err(|e| crate::Error::Keystore(format!("workspace verifier encrypt: {e}")))?;
        let value = enc
            .to_bech32()
            .map_err(|e| crate::Error::Keystore(format!("workspace verifier encode: {e}")))?;
        let path = self.workspace_verifier_path();
        fs::write(&path, value)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Verify the workspace passphrase even before the first agent exists.
    /// Returns false only when this call initializes a brand-new verifier.
    /// Legacy workspaces without a verifier are checked against an existing
    /// agent key first, then upgraded in place.
    pub fn verify_or_initialize_workspace(&self, passphrase: &str) -> Result<bool, crate::Error> {
        let marker = self.workspace_verifier_path();
        if marker.exists() {
            let raw = fs::read_to_string(&marker)?;
            let enc = EncryptedSecretKey::from_bech32(raw.trim()).map_err(|e| {
                crate::Error::Keystore(format!("workspace verifier is invalid: {e}"))
            })?;
            enc.decrypt(passphrase).map_err(|_| {
                crate::Error::Keystore("workspace passphrase does not match".into())
            })?;
            return Ok(true);
        }

        if let Some(first) = self.list()?.first() {
            self.load(first, passphrase)?;
            self.write_workspace_verifier(passphrase)?;
            return Ok(true);
        }

        self.write_workspace_verifier(passphrase)?;
        Ok(false)
    }

    pub fn agent_dir(&self, npub: &str) -> PathBuf {
        self.root.join(npub)
    }

    /// Persist a freshly generated identity, NIP-49 encrypted.
    pub fn store(&self, keys: &Keys, passphrase: &str) -> Result<PathBuf, crate::Error> {
        let npub = crate::identity::to_npub(&keys.public_key())?;
        let dir = self.agent_dir(&npub);
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        let enc = EncryptedSecretKey::new(keys.secret_key(), passphrase, 16, KeySecurity::Medium)
            .map_err(|e| crate::Error::Keystore(format!("nip49 encrypt: {e}")))?;
        let ncryptsec = enc
            .to_bech32()
            .map_err(|e| crate::Error::Keystore(format!("bech32: {e}")))?;
        let path = dir.join("key.ncryptsec");
        fs::write(&path, ncryptsec)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(path)
    }

    /// Load and decrypt an agent's keys for admission into custody.
    pub fn load(&self, npub: &str, passphrase: &str) -> Result<Keys, crate::Error> {
        let path = self.agent_dir(npub).join("key.ncryptsec");
        let ncryptsec = fs::read_to_string(&path)
            .map_err(|e| crate::Error::Keystore(format!("read {}: {e}", path.display())))?;
        let enc = EncryptedSecretKey::from_bech32(ncryptsec.trim())
            .map_err(|e| crate::Error::Keystore(format!("parse ncryptsec: {e}")))?;
        let sk = enc.decrypt(passphrase).map_err(|_| {
            crate::Error::Keystore(
                "encrypted key did not open with this workspace passphrase".into(),
            )
        })?;
        Ok(Keys::new(sk))
    }

    /// Enumerate stored agent npubs (directory names).
    pub fn list(&self) -> Result<Vec<String>, crate::Error> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("npub1") {
                        out.push(name.to_string());
                    }
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("apiary-ks-test-{}", std::process::id()));
        let ks = Keystore::open(&dir).unwrap();
        let keys = Keys::generate();
        ks.store(&keys, "correct horse").unwrap();
        let npub = crate::identity::to_npub(&keys.public_key()).unwrap();
        let loaded = ks.load(&npub, "correct horse").unwrap();
        assert_eq!(loaded.public_key(), keys.public_key());
        assert!(ks.load(&npub, "wrong").is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_workspace_passphrase_is_persistent_and_verifiable() {
        let dir = std::env::temp_dir().join(format!(
            "apiary-empty-workspace-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let ks = Keystore::open(&dir).unwrap();
        assert!(!ks
            .verify_or_initialize_workspace("first passphrase")
            .unwrap());
        assert!(ks
            .verify_or_initialize_workspace("first passphrase")
            .unwrap());
        assert!(ks
            .verify_or_initialize_workspace("different passphrase")
            .is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
