//! The agent manifest — SPEC §4.
//!
//! The agent *is* its manifest + key + memory. The manifest lives outside any
//! host's database: moving hosts is a file move, not a migration. Everything
//! capable is a connector (SPEC §6); the core has no capabilities, only custody.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current manifest schema version. Versioned from v1 (SPEC §8: the manifest
/// is a contract — the first schema change must not break deployed agents).
pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest_version: u32,
    pub identity: Identity,
    /// Inference is a POOL, not a scalar — each entry is a full connection
    /// ("inference in" is itself a credentialed connection, SPEC §1/§7).
    #[serde(default)]
    pub inference: Vec<InferenceSlot>,
    #[serde(default)]
    pub routing: Routing,
    /// Everything capable is a connector, incl. shell & payments. Absent
    /// connector = absent capability (default-deny by construction).
    #[serde(default)]
    pub connectors: Vec<Connector>,
    pub memory: Memory,
    #[serde(default)]
    pub presence: Presence,
    pub governance: Governance,
    /// Single-instance liveness (SPEC §8 split-brain, §12.2 takeover modes).
    #[serde(default)]
    pub lease: LeaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// The agent's public key — the identity itself (bech32 npub).
    pub npub: String,
    /// Master-key custody: a NIP-46 remote signer URI. Running instances get
    /// session-scoped delegation only; a stolen host is not a stolen identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// Successor-key statement, signed at founding — cheap now, forward
    /// compatible with whatever rotation NIP the ecosystem lands on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceSlot {
    /// Pool-local name routing rules refer to: "workhorse", "fast", "local", "embed".
    pub name: String,
    /// "anthropic" | "openai" | "ollama" | "host" (host-supplied: declare
    /// requirements, the host binds a concrete model per deployment).
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Agent-owned credential: NIP-44 blob encrypted to the agent's pubkey.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<EncryptedBlob>,
    /// For provider = "host": cognitive requirements instead of a credential.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub requires: BTreeMap<String, serde_json::Value>,
}

/// Agent-authored, human-governed routing (SPEC §7). Floors are human-signed
/// and agent-immutable; rules may tighten them, never loosen (HARD_FLOORS
/// clamp, generalized). Merge order: floors → rules → default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    #[serde(default)]
    pub floors: Vec<RoutingRule>,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    /// Declarative condition, e.g. `data.class == "sensitive"`.
    pub when: String,
    /// Target inference-slot name.
    pub to: String,
    /// Per-rule provenance (SPEC §7): authored-by / approved-by / evidenced-by.
    #[serde(default, skip_serializing_if = "Provenance::is_empty")]
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authored_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    /// Pointers into the episodic log — evidence-cited amendments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidenced_by: Vec<String>,
}

impl Provenance {
    pub fn is_empty(&self) -> bool {
        self.authored_by.is_none() && self.approved_by.is_none() && self.evidenced_by.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connector {
    /// "square", "shell-sandboxed", "cashu-wallet", …
    #[serde(rename = "type")]
    pub kind: String,
    /// NIP-44 blob encrypted to the agent's pubkey; useless without the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<EncryptedBlob>,
    /// Spend-authority floors and behavioral caps, human-owned.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub caps: BTreeMap<String, serde_json::Value>,
}

/// Memory is three stores with different sync/growth/privacy (SPEC §9).
/// The working set is ephemeral and deliberately absent from the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    /// Signed episodic log location (append-only), e.g. `relay://…` or a path.
    pub log: String,
    /// Semantic index location — derived, rebuildable.
    #[serde(default = "default_index")]
    pub index: String,
}

fn default_index() -> String {
    "local".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agui: Option<AguiPresence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AguiPresence {
    pub endpoint: String,
    /// Session auth scheme; "nip98" binds the AG-UI session to the npub.
    #[serde(default = "default_agui_auth")]
    pub auth: String,
}

fn default_agui_auth() -> String {
    "nip98".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Governance {
    /// Human keys that can halt the agent (SPEC §8). Suspension authority
    /// must never rest with the agent's own key.
    pub suspend_keys: Vec<String>,
    /// Unified spend authority: token budgets and money budgets are one
    /// system of human-owned floors enforced by the host core.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub budgets: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseConfig {
    /// Where liveness is asserted. "relay-event" = signed, replaceable
    /// "running on host X until T" event.
    #[serde(default = "default_lease_mechanism")]
    pub mechanism: String,
    /// Takeover policy (SPEC §12.2): "auto" | "human" | "contested-human".
    #[serde(default = "default_takeover")]
    pub takeover: String,
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_secs: u64,
    #[serde(default = "default_expiry_secs")]
    pub expiry_secs: u64,
}

impl Default for LeaseConfig {
    fn default() -> Self {
        Self {
            mechanism: default_lease_mechanism(),
            takeover: default_takeover(),
            heartbeat_secs: default_heartbeat_secs(),
            expiry_secs: default_expiry_secs(),
        }
    }
}

fn default_lease_mechanism() -> String {
    "relay-event".into()
}
fn default_takeover() -> String {
    "contested-human".into()
}
fn default_heartbeat_secs() -> u64 {
    300
}
fn default_expiry_secs() -> u64 {
    900
}

/// A NIP-44 ciphertext envelope. Portable; useless without the agent's key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedBlob {
    /// base64 NIP-44 v2 payload.
    pub nip44: String,
}

impl Manifest {
    pub fn from_yaml(s: &str) -> Result<Self, crate::Error> {
        let m: Manifest = serde_yaml::from_str(s)?;
        m.validate()?;
        Ok(m)
    }

    pub fn to_yaml(&self) -> Result<String, crate::Error> {
        Ok(serde_yaml::to_string(self)?)
    }

    /// Structural validation beyond serde: the invariants the substrate owns.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(crate::Error::Manifest(format!(
                "unsupported manifest_version {} (host supports {})",
                self.manifest_version, MANIFEST_VERSION
            )));
        }
        let agent_pk = crate::identity::parse_npub(&self.identity.npub)?;
        if self.governance.suspend_keys.is_empty() {
            return Err(crate::Error::Manifest(
                "governance.suspend_keys must name at least one human key: \
                 suspension authority can never rest with the agent's own key"
                    .into(),
            ));
        }
        // Suspend keys must be valid keys and must not include the agent itself.
        for k in &self.governance.suspend_keys {
            let pk = crate::identity::parse_npub(k)?;
            if pk == agent_pk {
                return Err(crate::Error::Manifest(
                    "agent's own key cannot be a suspend key".into(),
                ));
            }
        }
        // Routing targets must exist in the inference pool.
        let slot_names: Vec<&str> = self.inference.iter().map(|s| s.name.as_str()).collect();
        for rule in self.routing.floors.iter().chain(self.routing.rules.iter()) {
            if !slot_names.contains(&rule.to.as_str()) {
                return Err(crate::Error::Manifest(format!(
                    "routing rule targets unknown inference slot '{}'",
                    rule.to
                )));
            }
        }
        if let Some(d) = &self.routing.default {
            if !slot_names.contains(&d.as_str()) {
                return Err(crate::Error::Manifest(format!(
                    "routing default targets unknown inference slot '{d}'"
                )));
            }
        }
        // Duplicate slot names would make routing ambiguous.
        let mut seen = std::collections::BTreeSet::new();
        for n in &slot_names {
            if !seen.insert(*n) {
                return Err(crate::Error::Manifest(format!(
                    "duplicate inference slot name '{n}'"
                )));
            }
        }
        Ok(())
    }
}
