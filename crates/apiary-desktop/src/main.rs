//! Apiary desktop — the cockpit as a native window (SPEC §2: the GUI is a
//! client). The full hostd router runs IN-PROCESS on a loopback ephemeral
//! port, gated by a per-launch random token that only this window's boot
//! URL carries — so the embedded daemon is not silently drivable by other
//! local processes, and custody still never leaves the host process.
//!
//! Environment (all optional):
//!   APIARY_HOME        state directory (default ~/.apiary)
//!   APIARY_PASSPHRASE  development migration/unlock input (removed from env;
//!                      desktop launch unlock is stored in macOS Keychain)
//!   ANTHROPIC_API_KEY  enables anthropic-routed runs + manifest drafting

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use apiary_hostd::{build_router, AppState, AuthMode};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

const KEYCHAIN_SERVICE: &str = "wine.wisco.apiary.keystore";

fn default_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".apiary")
}

fn keychain_account(home: &std::path::Path) -> String {
    home.to_string_lossy().into_owned()
}

#[cfg(target_os = "macos")]
fn keychain_load(home: &std::path::Path) -> Option<String> {
    let bytes = security_framework::passwords::get_generic_password(
        KEYCHAIN_SERVICE,
        &keychain_account(home),
    )
    .ok()?;
    let bytes = Zeroizing::new(bytes);
    String::from_utf8(bytes.to_vec())
        .ok()
        .filter(|passphrase| !passphrase.is_empty())
}

#[cfg(not(target_os = "macos"))]
fn keychain_load(_home: &std::path::Path) -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn keychain_store(home: &std::path::Path, passphrase: &str) -> Result<(), String> {
    security_framework::passwords::set_generic_password(
        KEYCHAIN_SERVICE,
        &keychain_account(home),
        passphrase.as_bytes(),
    )
    .map_err(|error| format!("macOS Keychain: {error}"))
}

#[cfg(not(target_os = "macos"))]
fn keychain_store(_home: &std::path::Path, _passphrase: &str) -> Result<(), String> {
    Err("automatic unlock is available only in the macOS desktop app".into())
}

#[cfg(target_os = "macos")]
fn keychain_delete(home: &std::path::Path) -> Result<(), String> {
    security_framework::passwords::delete_generic_password(
        KEYCHAIN_SERVICE,
        &keychain_account(home),
    )
    .map_err(|error| format!("macOS Keychain: {error}"))
}

#[cfg(not(target_os = "macos"))]
fn keychain_delete(_home: &std::path::Path) -> Result<(), String> {
    Err("automatic unlock is available only in the macOS desktop app".into())
}

fn startup_passphrase(home: &std::path::Path) -> (Option<String>, bool) {
    let from_environment = std::env::var("APIARY_PASSPHRASE")
        .ok()
        .filter(|passphrase| !passphrase.is_empty());
    std::env::remove_var("APIARY_PASSPHRASE");
    if let Some(passphrase) = from_environment {
        let remembered = keychain_store(home, &passphrase).is_ok();
        return (Some(passphrase), remembered);
    }
    match keychain_load(home) {
        Some(passphrase) => (Some(passphrase), true),
        None => (None, false),
    }
}

fn main() {
    let home = std::env::var_os("APIARY_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(default_home);
    let (startup_passphrase, automatic_unlock) = startup_passphrase(&home);
    let remember_home = home.clone();
    let remember_passphrase: apiary_hostd::RememberPassphrase =
        Arc::new(move |passphrase| keychain_store(&remember_home, passphrase));
    let forget_home = home.clone();
    let forget_passphrase: apiary_hostd::ForgetPassphrase =
        Arc::new(move || keychain_delete(&forget_home));
    let home_for_discovery = home.clone();
    // 32 random bytes, hex — a fresh nostr secret key is exactly that, and
    // the keygen path is already audited. Never stored, never logged.
    let token = apiary_core::identity::generate()
        .secret_key()
        .to_secret_hex();

    // Reserve the port before building state so the NIP-98 origin (unused
    // in open mode, but kept truthful) matches reality.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    std_listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let port = std_listener.local_addr().expect("local addr").port();

    let state = Arc::new(AppState {
        home,
        passphrase: std::sync::RwLock::new(startup_passphrase),
        remember_passphrase: Some(remember_passphrase),
        forget_passphrase: Some(forget_passphrase),
        automatic_unlock: std::sync::atomic::AtomicBool::new(automatic_unlock),
        auth: AuthMode::Open,
        origin: format!("http://127.0.0.1:{port}"),
        token: Some(token.clone()),
        listeners: std::sync::Mutex::new(std::collections::HashMap::new()),
        pending_oauth: std::sync::Mutex::new(std::collections::HashMap::new()),
        supervisor_notes: std::sync::Mutex::new(std::collections::HashMap::new()),
        admitted: std::sync::Mutex::new(std::collections::HashMap::new()),
        // Desktop runs open-mode behind its per-launch token; the token
        // IS the admin boundary there.
        admins: Vec::new(),
    });

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).expect("adopt listener");
            // Presence supervisor: active agents with declared presence.buzz
            // get their listener started, restarted, and stopped by the host.
            apiary_hostd::ops::spawn_supervisor(state.clone());
            axum::serve(listener, build_router(state))
                .await
                .expect("serve");
        });
    });

    // Local discovery for companions (apiary-voice etc.): where this
    // desktop's daemon is and the token that admits a caller. 0600 in the
    // Apiary home — the same trust boundary as the keystore beside it —
    // and removed on clean exit. A companion that can read this file is
    // the same user who unlocked the keystore.
    let discovery = state_home_discovery_path(&home_for_discovery);
    write_discovery(&discovery, port, &token);
    let discovery_for_exit = discovery.clone();

    let url = format!("http://127.0.0.1:{port}/?token={token}");
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            // The cockpit's "Choose…" buttons ask the daemon, which asks us
            // for the native folder dialog (called from a blocking task,
            // never the main thread).
            let handle = app.handle().clone();
            apiary_hostd::ops::set_folder_picker(Box::new(move || {
                use tauri_plugin_dialog::DialogExt;
                handle
                    .dialog()
                    .file()
                    .blocking_pick_folder()
                    .map(|p| p.to_string())
            }));
            tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::External(url.parse().expect("boot url")),
            )
            .title("Apiary")
            .inner_size(1360.0, 900.0)
            .min_inner_size(720.0, 520.0)
            .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("apiary desktop");
    let _ = std::fs::remove_file(discovery_for_exit);
}

fn state_home_discovery_path(home: &std::path::Path) -> PathBuf {
    home.join("desktop.json")
}

fn write_discovery(path: &std::path::Path, port: u16, token: &str) {
    let body = serde_json::json!({
        "url": format!("http://127.0.0.1:{port}"),
        "token": token,
        "pid": std::process::id(),
    });
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")));
    if std::fs::write(path, body.to_string()).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
    }
}
