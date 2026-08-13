//! Custody — SPEC §5, with the per-agent isolation requirement of SPEC §2:
//! "Agent A must never touch agent B's key material or decrypted secrets."
//!
//! Isolation is structural, not policy: every operation requires an
//! [`AgentHandle`], which can only be obtained by admitting that agent's keys,
//! and each operation reaches only that agent's keyring. There is no API to
//! enumerate other agents' keys or to decrypt across handles.
//!
//! Phase 0 custody holds keys in-process (dev keystore, NIP-49 encrypted at
//! rest — see `keystore`). The NIP-46 remote-signer path replaces the key
//! source later without changing this API: handles stay, material moves out.

use nostr::nips::nip44::{self, Version};
use nostr::prelude::*;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::manifest::EncryptedBlob;

/// Opaque, unforgeable-within-the-process reference to one admitted agent.
/// Not Clone into other agents' scopes by accident: it's just a pubkey, but
/// custody operations verify admission on every call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentHandle(PublicKey);

impl AgentHandle {
    pub fn pubkey(&self) -> &PublicKey {
        &self.0
    }
}

struct AgentKeyring {
    keys: Keys,
}

/// The custody core. One per host process.
#[derive(Default)]
pub struct Custody {
    agents: BTreeMap<PublicKey, AgentKeyring>,
}

impl Custody {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit an agent's keys into custody, returning the handle that scopes
    /// every subsequent operation to exactly this agent.
    pub fn admit(&mut self, keys: Keys) -> AgentHandle {
        let pk = keys.public_key();
        self.agents.insert(pk, AgentKeyring { keys });
        AgentHandle(pk)
    }

    /// Drop an agent's key material (suspend event / shutdown path: SPEC §8
    /// requires "drops decrypted material" — this drops the keys themselves).
    pub fn evict(&mut self, handle: &AgentHandle) {
        self.agents.remove(&handle.0);
    }

    fn keyring(&self, handle: &AgentHandle) -> Result<&AgentKeyring, crate::Error> {
        self.agents
            .get(&handle.0)
            .ok_or_else(|| crate::Error::Custody("agent not admitted to custody".into()))
    }

    /// Seal a credential to this agent (NIP-44, self-conversation). The blob
    /// is portable and useless without the agent's key — SPEC §5.
    pub fn seal(&self, handle: &AgentHandle, plaintext: &str) -> Result<EncryptedBlob, crate::Error> {
        let kr = self.keyring(handle)?;
        let ct = nip44::encrypt(kr.keys.secret_key(), &kr.keys.public_key(), plaintext, Version::V2)
            .map_err(|e| crate::Error::Custody(format!("nip44 encrypt: {e}")))?;
        Ok(EncryptedBlob { nip44: ct })
    }

    /// Just-in-time decrypt: plaintext exists transiently, per-credential, at
    /// call time only (SPEC §5). Returned buffer zeroizes on drop.
    pub fn open(
        &self,
        handle: &AgentHandle,
        blob: &EncryptedBlob,
    ) -> Result<Zeroizing<String>, crate::Error> {
        let kr = self.keyring(handle)?;
        let pt = nip44::decrypt(kr.keys.secret_key(), &kr.keys.public_key(), &blob.nip44)
            .map_err(|e| crate::Error::Custody(format!("nip44 decrypt: {e}")))?;
        Ok(Zeroizing::new(pt))
    }

    /// Sign an event as this agent (founding statements, log entries, leases).
    pub fn sign(&self, handle: &AgentHandle, builder: EventBuilder) -> Result<Event, crate::Error> {
        let kr = self.keyring(handle)?;
        builder
            .finalize(&kr.keys)
            .map_err(|e| crate::Error::Custody(format!("sign: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let mut custody = Custody::new();
        let handle = custody.admit(Keys::generate());
        let blob = custody.seal(&handle, "sq_secret_token").unwrap();
        assert_ne!(blob.nip44, "sq_secret_token");
        let opened = custody.open(&handle, &blob).unwrap();
        assert_eq!(opened.as_str(), "sq_secret_token");
    }

    #[test]
    fn isolation_agent_a_cannot_open_agent_b_blob() {
        let mut custody = Custody::new();
        let a = custody.admit(Keys::generate());
        let b = custody.admit(Keys::generate());
        let blob = custody.seal(&b, "b_only").unwrap();
        // A's handle reaches only A's keyring; B's blob must not decrypt.
        assert!(custody.open(&a, &blob).is_err());
    }

    #[test]
    fn evicted_agent_cannot_decrypt() {
        let mut custody = Custody::new();
        let handle = custody.admit(Keys::generate());
        let blob = custody.seal(&handle, "gone").unwrap();
        custody.evict(&handle);
        assert!(custody.open(&handle, &blob).is_err());
    }
}
