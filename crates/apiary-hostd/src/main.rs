//! The `apiary-hostd` binary: parse args, build the shared router, serve.
//! All behavior lives in the library — the Tauri desktop app embeds the
//! same router in-process.

use apiary_hostd::{build_router, AppState, AuthMode};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "apiary-hostd", version, about = "Apiary host daemon")]
struct Args {
    /// State directory (keys, manifests).
    #[arg(long, env = "APIARY_HOME", default_value_os_t = default_home())]
    home: PathBuf,
    /// Dev-keystore passphrase; the cockpit can also unlock at runtime.
    #[arg(long, env = "APIARY_PASSPHRASE", hide_env_values = true)]
    passphrase: Option<String>,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:7777")]
    bind: String,
    /// Auth mode: "open" (localhost dev) or "nip98" (signed requests).
    #[arg(long, default_value = "open")]
    auth: String,
    /// Canonical external origin clients sign NIP-98 URLs against
    /// (default: http://<bind>). Must match what clients see exactly.
    #[arg(long)]
    origin: Option<String>,
    /// Bootstrap host-manager npubs (nip98 mode). Repeatable. Managers added
    /// later in People & access persist, so this flag is only required for
    /// first setup or recovery.
    #[arg(long = "admin")]
    admins: Vec<String>,
}

fn default_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".apiary")
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // Fail closed: an unrecognized auth mode must never silently mean open.
    let auth = match args.auth.as_str() {
        "nip98" => AuthMode::Nip98,
        "open" => {
            eprintln!("auth=open: every local process can drive this daemon; use --auth nip98 beyond localhost dev");
            AuthMode::Open
        }
        other => {
            eprintln!("error: unknown --auth '{other}' (expected: open | nip98)");
            std::process::exit(2);
        }
    };
    let admins = args
        .admins
        .iter()
        .map(|a| apiary_core::identity::parse_npub(a))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| {
            eprintln!("error: --admin: {e}");
            std::process::exit(2);
        });
    let managers =
        apiary_hostd::access::ManagerRegistry::load(&args.home, admins).unwrap_or_else(|error| {
            eprintln!("error: host manager registry: {error}");
            std::process::exit(2);
        });
    let state = Arc::new(AppState {
        home: args.home.clone(),
        passphrase: std::sync::RwLock::new(args.passphrase.clone()),
        remember_passphrase: None,
        forget_passphrase: None,
        automatic_unlock: std::sync::atomic::AtomicBool::new(false),
        auth,
        origin: args
            .origin
            .clone()
            .unwrap_or_else(|| format!("http://{}", args.bind)),
        token: None,
        internal_token: apiary_core::identity::generate()
            .secret_key()
            .to_secret_hex(),
        control_audit: std::sync::Mutex::new(()),
        control_tokens: std::sync::Mutex::new(()),
        listeners: std::sync::Mutex::new(std::collections::HashMap::new()),
        pending_oauth: std::sync::Mutex::new(std::collections::HashMap::new()),
        supervisor_notes: std::sync::Mutex::new(std::collections::HashMap::new()),
        admitted: std::sync::Mutex::new(std::collections::HashMap::new()),
        managers: std::sync::RwLock::new(managers),
    });
    apiary_hostd::write_control_discovery(&state).unwrap_or_else(|error| {
        eprintln!("error: control-plane discovery: {error}");
        std::process::exit(2);
    });
    apiary_hostd::ops::spawn_supervisor(state.clone());
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .expect("bind");
    println!("apiary-hostd listening on http://{}", args.bind);
    axum::serve(listener, app).await.expect("serve");
}
