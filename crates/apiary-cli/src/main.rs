//! `apiary` — the host's front door. JSON in/out, `buzz-cli`-style, so the
//! host is scriptable by humans and drivable by agents (SPEC §2). This is the
//! HOST surface; agents' own shell access is an opt-in connector (SPEC §6) and
//! has nothing to do with this binary.

use apiary_core::{custody::Custody, keystore::Keystore, manifest::Manifest};
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
                let raw = std::fs::read_to_string(ks.agent_dir(npub).join("manifest.yaml"))?;
                let m = Manifest::from_yaml(&raw)?;
                Ok(json!({"ok": true, "manifest": serde_json::to_value(&m)?}))
            }
        },
        Command::Credential { cmd } => match cmd {
            CredentialCmd::Seal { npub } => {
                let passphrase = require_passphrase(cli)?;
                let keys = ks.load(npub, passphrase)?;
                let mut custody = Custody::new();
                let handle = custody.admit(keys);
                let plaintext = read_stdin()?;
                let blob = custody.seal(&handle, plaintext.trim_end())?;
                Ok(json!({"ok": true, "npub": npub, "nip44": blob.nip44}))
            }
            CredentialCmd::Open { npub } => {
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
