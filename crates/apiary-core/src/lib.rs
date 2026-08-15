//! apiary-core — the portable-agent substrate (SPEC §2).
//!
//! The core has no capabilities, only custody: manifest, identity, and
//! per-agent-isolated key material. Every capability is a connector declared
//! in the manifest; the host enforces floors the model cannot argue with.

pub mod ceremony;
pub mod custody;
pub mod identity;
pub mod keystore;
pub mod log;
pub mod manifest;
pub mod portability;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("identity: {0}")]
    Identity(String),
    #[error("custody: {0}")]
    Custody(String),
    #[error("keystore: {0}")]
    Keystore(String),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
