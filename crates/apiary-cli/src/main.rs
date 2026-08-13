//! `apiary` — the host's front door. JSON in/out, `buzz-cli`-style, so the
//! host is scriptable by humans and drivable by agents (SPEC §2). This is the
//! HOST surface; agents' own shell access is an opt-in connector (SPEC §6) and
//! has nothing to do with this binary.

use apiary_core::{ceremony, custody::Custody, keystore::Keystore, log::EpisodicLog, manifest::Manifest};
use nostr::prelude::*;
use clap::{Parser, Subcommand};
use serde_json::json;
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "apiary", version, about = "Apiary portable-agent host")]
struct Cli {
    /// State directory (keys, manifests). Never commit this.
    #[arg(long, env = "APIARY_HOME", default_value_os_t = default_home())]
    home: PathBuf,
    /// Dev-keystore passphrase (NIP-49). Prefer the env var over the flag.
    #[arg(long, env = "APIARY_PASSPHRASE", hide_env_values = true, global = true)]
    passphrase: Option<String>,
    #[command(subcommand)]
    command: Command,
}

fn default_home() -> PathBuf {
    dirs_home().join(".apiary")
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[derive(Subcommand)]
enum Command {
    /// Agent lifecycle.
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },
    /// Manifest operations.
    Manifest {
        #[command(subcommand)]
        cmd: ManifestCmd,
    },
    /// Credential custody (NIP-44 seal/open against an agent's key).
    Credential {
        #[command(subcommand)]
        cmd: CredentialCmd,
    },
    /// The signed episodic log.
    Log {
        #[command(subcommand)]
        cmd: LogCmd,
    },
    /// Normalize a public key: accepts npub or hex, prints both forms.
    Key { key: String },
    /// Run a one-shot task as an agent.
    Run {
        /// The agent's npub.
        npub: String,
        /// The task text.
        #[arg(long)]
        task: String,
        /// Task class for routing (e.g. "reasoning").
        #[arg(long)]
        class: Option<String>,
        /// Data class for routing floors (e.g. "sensitive").
        #[arg(long)]
        data_class: Option<String>,
    },
}

#[derive(Subcommand)]
enum LogCmd {
    /// Show the last N log entries.
    Show {
        npub: String,
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    /// Verify every entry's signature and the prev-chain.
    Verify { npub: String },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Found a new agent: generate identity, store key (NIP-49), write a
    /// provisional manifest. Founding is the moment of maximum ignorance —
    /// the manifest starts minimal and conservative (SPEC §7).
    New {
        /// Human-readable label (stored in the manifest directory only).
        #[arg(long)]
        name: Option<String>,
        /// Human suspend key (npub). Required: suspension authority can never
        /// rest with the agent's own key (SPEC §8).
        #[arg(long, required = true)]
        suspend_key: Vec<String>,
    },
    /// List agents in this host's keystore.
    List,
    /// Ratify an agent's manifest as a human suspend-key holder. The agent
    /// signs its manifest hash, then the human countersigns — both land as
    /// public log entries (the founding ceremony, SPEC §7).
    Ratify {
        /// The agent's npub.
        npub: String,
        /// The ratifying human's npub. Without --export/--import the key must
        /// be held in this keystore and listed in governance.suspend_keys.
        #[arg(long = "as", value_name = "NPUB")]
        as_key: Option<String>,
        /// Emit the UNSIGNED ratification event for external signing (your
        /// master key never enters Apiary). Requires --as for the signer.
        #[arg(long)]
        export: bool,
        /// Import an externally-signed ratification event (JSON on stdin).
        #[arg(long)]
        import: bool,
    },
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Validate a manifest file (schema + substrate invariants).
    Validate { path: PathBuf },
    /// Print an agent's manifest as JSON.
    Show { npub: String },
}

#[derive(Subcommand)]
enum CredentialCmd {
    /// Seal a secret to an agent's key. Reads plaintext from stdin; emits the
    /// NIP-44 blob for pasting into a manifest connector entry.
    Seal { npub: String },
    /// Open a sealed blob (stdin) with an agent's key. Dev/debug only —
    /// prints plaintext to stdout, so pipe it, don't paste it.
    Open { npub: String },
}

fn main() {
    let cli = Cli::parse();
    let result = run(&cli);
    match result {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({"ok": false, "error": e.to_string()})).unwrap()
            );
            std::process::exit(1);
        }
    }
}

fn run(cli: &Cli) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let ks = Keystore::open(&cli.home)?;
    match &cli.command {
        Command::Agent { cmd } => match cmd {
            AgentCmd::New { name, suspend_key } => {
                // Validate suspend keys before generating anything.
                for k in suspend_key {
                    apiary_core::identity::parse_npub(k)?;
                }
                let passphrase = require_passphrase(cli)?;
                let keys = apiary_core::identity::generate();
                let npub = apiary_core::identity::to_npub(&keys.public_key())?;
                let key_path = ks.store(&keys, passphrase)?;

                let manifest = Manifest::from_yaml(&founding_manifest_yaml(&npub, suspend_key))?;
                let dir = ks.agent_dir(&npub);
                let manifest_path = dir.join("manifest.yaml");
                std::fs::write(&manifest_path, manifest.to_yaml()?)?;
                if let Some(n) = name {
                    std::fs::write(dir.join("name"), n)?;
                }
                Ok(json!({
                    "ok": true,
                    "npub": npub,
                    "name": name,
                    "key": key_path.display().to_string(),
                    "manifest": manifest_path.display().to_string(),
                    "note": "provisional manifest — founding is the moment of maximum ignorance; ratify and amend"
                }))
            }
            AgentCmd::Ratify { npub, as_key, export, import } => {
                let npub = &normalize_key(npub)?;
                let raw = std::fs::read_to_string(ks.agent_dir(npub).join("manifest.yaml"))?;
                let manifest = Manifest::from_yaml(&raw)?;
                let listed = manifest
                    .governance
                    .suspend_keys
                    .iter()
                    .map(|k| apiary_core::identity::parse_npub(k))
                    .collect::<Result<Vec<_>, _>>()?;
                let log = EpisodicLog::open(&ks.agent_dir(npub));

                if *import {
                    // Externally-signed event on stdin; verify + append.
                    let event = Event::from_json(read_stdin()?.trim())
                        .map_err(|e| format!("could not parse event JSON: {e}"))?;
                    ceremony::import_ratification(&log, &event, &raw, &listed)?;
                    return Ok(json!({
                        "ok": true,
                        "agent": npub,
                        "imported": event.id.to_hex(),
                        "ratified_by": event.pubkey.to_hex(),
                        "manifest_sha256": ceremony::manifest_hash(&raw),
                    }));
                }

                let as_key_raw = as_key
                    .as_deref()
                    .ok_or("--as <npub> is required (the ratifying human)")?;
                let as_key = &normalize_key(as_key_raw)?;
                let ratifier_pk = apiary_core::identity::parse_npub(as_key)?;
                if !listed.contains(&ratifier_pk) {
                    return Err(format!(
                        "{as_key} is not in this agent's governance.suspend_keys — \
                         only a named human can ratify"
                    )
                    .into());
                }

                if *export {
                    // Emit the unsigned event; the human signs it elsewhere.
                    let unsigned =
                        ceremony::ratification_unsigned(ratifier_pk, npub, &raw)?;
                    return Ok(json!({
                        "ok": true,
                        "agent": npub,
                        "sign_as": as_key,
                        "unsigned_event": serde_json::from_str::<serde_json::Value>(&unsigned.as_json())?,
                        "note": "sign this with your own nostr tooling, then: apiary agent ratify <npub> --import < signed.json"
                    }));
                }

                let passphrase = require_passphrase(cli)?;
                let mut custody = Custody::new();
                let agent_handle = custody.admit(ks.load(npub, passphrase)?);
                let human_handle = custody.admit(ks.load(as_key, passphrase)?);
                let signed = ceremony::sign_manifest(&custody, &agent_handle, &log, &raw)?;
                let ratified = ceremony::ratify(&custody, &human_handle, &log, npub, &raw)?;
                Ok(json!({
                    "ok": true,
                    "agent": npub,
                    "ratified_by": as_key,
                    "manifest_sha256": ceremony::manifest_hash(&raw),
                    "events": { "signed": signed.id.to_hex(), "ratified": ratified.id.to_hex() },
                }))
            }
            AgentCmd::List => {
                let agents: Vec<serde_json::Value> = ks
                    .list()?
                    .into_iter()
                    .map(|npub| {
                        let name = std::fs::read_to_string(ks.agent_dir(&npub).join("name")).ok();
                        json!({"npub": npub, "name": name})
                    })
                    .collect();
                Ok(json!({"ok": true, "agents": agents}))
            }
        },
        Command::Manifest { cmd } => match cmd {
            ManifestCmd::Validate { path } => {
                let raw = std::fs::read_to_string(path)?;
                let m = Manifest::from_yaml(&raw)?;
                Ok(json!({"ok": true, "npub": m.identity.npub, "valid": true}))
            }
            ManifestCmd::Show { npub } => {
                let npub = &normalize_key(npub)?;
                let raw = std::fs::read_to_string(ks.agent_dir(npub).join("manifest.yaml"))?;
                let m = Manifest::from_yaml(&raw)?;
                Ok(json!({"ok": true, "manifest": serde_json::to_value(&m)?}))
            }
        },
        Command::Log { cmd } => match cmd {
            LogCmd::Show { npub, tail } => {
                let npub = &normalize_key(npub)?;
                let log = EpisodicLog::open(&ks.agent_dir(npub));
                let entries: Vec<serde_json::Value> = log
                    .tail(*tail)?
                    .iter()
                    .map(|e| {
                        let body = EpisodicLog::parse_body(e).ok();
                        json!({
                            "id": e.id.to_hex(),
                            "at": e.created_at.as_secs(),
                            "signer": e.pubkey.to_hex(),
                            "body": body,
                        })
                    })
                    .collect();
                Ok(json!({"ok": true, "npub": npub, "entries": entries}))
            }
            LogCmd::Verify { npub } => {
                let npub = &normalize_key(npub)?;
                let count = EpisodicLog::open(&ks.agent_dir(npub)).verify()?;
                Ok(json!({"ok": true, "npub": npub, "entries": count, "chain": "valid"}))
            }
        },
        Command::Key { key } => {
            let pk = apiary_core::identity::parse_npub(key)?;
            let npub = apiary_core::identity::to_npub(&pk)?;
            let in_keystore = ks.agent_dir(&npub).join("key.ncryptsec").exists();
            Ok(json!({
                "ok": true,
                "npub": npub,
                "hex": pk.to_hex(),
                "in_keystore": in_keystore,
            }))
        }
        Command::Run { npub, task, class, data_class } => {
            let npub = &normalize_key(npub)?;
            let passphrase = require_passphrase(cli)?;
            let agent_dir = ks.agent_dir(npub);
            let raw = std::fs::read_to_string(agent_dir.join("manifest.yaml"))?;
            let manifest = Manifest::from_yaml(&raw)?;
            // Ratification gate: an unratified constitution doesn't run.
            let suspend_keys = manifest
                .governance
                .suspend_keys
                .iter()
                .map(|k| apiary_core::identity::parse_npub(k))
                .collect::<Result<Vec<_>, _>>()?;
            let log = EpisodicLog::open(&agent_dir);
            if !ceremony::is_ratified(&log, &raw, &suspend_keys)? {
                return Err(
                    "manifest is not ratified — run `apiary agent ratify` first \
                     (founding is constitution-then-amendments; nothing runs unratified)"
                        .into(),
                );
            }
            let mut custody = Custody::new();
            let handle = custody.admit(ks.load(npub, passphrase)?);
            let ctx = apiary_runtime::routing::TaskContext {
                task_class: class.clone(),
                data_class: data_class.clone(),
            };
            let out = apiary_runtime::runner::run_task(
                &manifest, &agent_dir, &custody, &handle, task, &ctx,
            )?;
            Ok(json!({
                "ok": true,
                "npub": npub,
                "slot": out.slot,
                "model": out.completion.model,
                "outcome": out.completion.outcome,
                "tokens": {
                    "input": out.completion.input_tokens,
                    "output": out.completion.output_tokens,
                },
                "log_event": out.log_event_id,
                "response": out.completion.text,
            }))
        }
        Command::Credential { cmd } => match cmd {
            CredentialCmd::Seal { npub } => {
                let npub = &normalize_key(npub)?;
                let passphrase = require_passphrase(cli)?;
                let keys = ks.load(npub, passphrase)?;
                let mut custody = Custody::new();
                let handle = custody.admit(keys);
                let plaintext = read_stdin()?;
                let blob = custody.seal(&handle, plaintext.trim_end())?;
                Ok(json!({"ok": true, "npub": npub, "nip44": blob.nip44}))
            }
            CredentialCmd::Open { npub } => {
                let npub = &normalize_key(npub)?;
                let passphrase = require_passphrase(cli)?;
                let keys = ks.load(npub, passphrase)?;
                let mut custody = Custody::new();
                let handle = custody.admit(keys);
                let blob = apiary_core::manifest::EncryptedBlob {
                    nip44: read_stdin()?.trim().to_string(),
                };
                let plaintext = custody.open(&handle, &blob)?;
                Ok(json!({"ok": true, "npub": npub, "plaintext": plaintext.as_str()}))
            }
        },
    }
}

/// Accept a public key in any form (npub or hex) and normalize to the
/// canonical npub, which is how keystore directories are named.
fn normalize_key(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let pk = apiary_core::identity::parse_npub(s)?;
    Ok(apiary_core::identity::to_npub(&pk)?)
}

fn require_passphrase(cli: &Cli) -> Result<&str, Box<dyn std::error::Error>> {
    cli.passphrase
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| "passphrase required: set APIARY_PASSPHRASE or --passphrase".into())
}

fn read_stdin() -> Result<String, std::io::Error> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// The minimal founding manifest: identity, memory, inference — and nothing
/// else until declared and ratified (SPEC §6: the capability floor for a
/// freshly founded agent is genuinely minimal).
fn founding_manifest_yaml(npub: &str, suspend_keys: &[String]) -> String {
    let keys_yaml: String = suspend_keys
        .iter()
        .map(|k| format!("    - {k}\n"))
        .collect();
    format!(
        "manifest_version: 1\n\
         identity:\n\
         \x20 npub: {npub}\n\
         inference: []\n\
         connectors: []\n\
         memory:\n\
         \x20 log: local\n\
         \x20 index: local\n\
         governance:\n\
         \x20 suspend_keys:\n{keys_yaml}"
    )
}
