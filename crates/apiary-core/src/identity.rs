//! Identity — SPEC §3. The keypair *is* the identity.

use nostr::prelude::*;

/// Generate a fresh agent identity (secp256k1 keypair).
pub fn generate() -> Keys {
    Keys::generate()
}

/// Parse a public key from npub/hex. All manifest key fields go through this.
pub fn parse_npub(s: &str) -> Result<PublicKey, crate::Error> {
    PublicKey::parse(s).map_err(|e| crate::Error::Identity(format!("invalid key '{s}': {e}")))
}

/// Canonical bech32 (npub) rendering for storage and display.
pub fn to_npub(pk: &PublicKey) -> Result<String, crate::Error> {
    pk.to_bech32()
        .map_err(|e| crate::Error::Identity(format!("bech32 encode failed: {e}")))
}
