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
    root: PathBuf,
}

impl Keystore {
    /// Open (creating if needed) a keystore rooted at `<state_dir>/agents`.
    pub fn open(state_dir: &Path) -> Result<Self, crate::Error> {
        let root = state_dir.join("agents");
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn agent_dir(&self, npub: &str) -> PathBuf {
        self.root.join(npub)
    }

    /// Persist a freshly generated identity, NIP-49 encrypted.
    pub fn store(&self, keys: &Keys, passphrase: &str) -> Result<PathBuf, crate::Error> {
        let npub = crate::identity::to_npub(&keys.public_key())?;
        let dir = self.agent_dir(&npub);
        fs::create_dir_all(&dir)?;
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
        let sk = enc
            .decrypt(passphrase)
            .map_err(|e| crate::Error::Keystore(format!("nip49 decrypt (wrong passphrase?): {e}")))?;
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
}
