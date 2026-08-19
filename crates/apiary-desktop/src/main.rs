//! Apiary desktop — the cockpit as a native window (SPEC §2: the GUI is a
//! client). In local mode the full hostd router runs IN-PROCESS on a
//! loopback ephemeral port, gated by a per-launch random token that only
//! this window's boot URL carries. In remote mode the window reaches a
//! headless host through an SSH loopback tunnel; the server remains the
//! sole owner of custody, connectors, channels, and execution.
//!
//! Environment (all optional):
//!   APIARY_HOME        state directory (default ~/.apiary)
//!   APIARY_PASSPHRASE  development migration/unlock input (removed from env;
//!                      desktop launch unlock is stored in macOS Keychain)
//!   ANTHROPIC_API_KEY  enables anthropic-routed runs + manifest drafting
//!   APIARY_REMOTE_SSH  optional SSH destination (user@host) for remote mode

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use apiary_hostd::{build_router, AppState, AuthMode};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use zeroize::Zeroizing;

const KEYCHAIN_SERVICE: &str = "wine.wisco.apiary.keystore";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DesktopConfig {
    #[serde(default)]
    mode: DesktopMode,
    #[serde(default)]
    remote: Option<RemoteConfig>,
    #[serde(default)]
    active_remote: Option<String>,
    #[serde(default)]
    remotes: Vec<SavedRemote>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DesktopMode {
    #[default]
    Local,
    Remote,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteConfig {
    ssh_target: String,
    #[serde(default)]
    ssh_port: Option<u16>,
    #[serde(default = "default_remote_port")]
    remote_port: u16,
    #[serde(default = "default_remote_port")]
    local_port: u16,
    #[serde(default)]
    identity_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedRemote {
    id: String,
    name: String,
    #[serde(flatten)]
    remote: RemoteConfig,
}

#[derive(Clone, Debug, Serialize)]
struct DesktopBootstrap {
    mode: DesktopMode,
    active_remote: Option<String>,
    remotes: Vec<DesktopRemoteView>,
    environment_override: bool,
}

#[derive(Clone, Debug, Serialize)]
struct DesktopRemoteView {
    id: String,
    name: String,
    ssh_target: String,
}

struct LaunchConfig {
    remote: Option<RemoteConfig>,
    bootstrap: DesktopBootstrap,
}

struct PendingDesktopAction {
    title: String,
    message: String,
    config: Option<DesktopConfig>,
}

fn default_remote_port() -> u16 {
    7777
}

struct SshTunnel {
    child: Child,
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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
    match load_launch_config(&home) {
        Ok(LaunchConfig {
            remote: Some(remote),
            bootstrap,
        }) => run_remote(home, remote, bootstrap),
        Ok(LaunchConfig {
            remote: None,
            bootstrap,
        }) => run_local(home, bootstrap),
        Err(error) => startup_error("Remote configuration error", error, 2),
    }
}

fn run_local(home: PathBuf, bootstrap: DesktopBootstrap) {
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

    let managers = apiary_hostd::access::ManagerRegistry::load(&home, Vec::new())
        .unwrap_or_else(|error| startup_error("Manager registry error", error, 2));
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
        // IS the request boundary there. Stored manager npubs become the
        // NIP-98 allowlist when this home later runs headless.
        managers: std::sync::RwLock::new(managers),
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
    write_discovery(&discovery, port, Some(&token), None);
    let discovery_for_exit = discovery.clone();

    let url = format!("http://127.0.0.1:{port}/?token={token}");
    run_window(url, true, home_for_discovery, bootstrap);
    let _ = std::fs::remove_file(discovery_for_exit);
}

fn run_remote(home: PathBuf, remote: RemoteConfig, bootstrap: DesktopBootstrap) {
    validate_remote(&remote)
        .unwrap_or_else(|error| startup_error("Remote configuration error", error, 2));
    let mut tunnel = start_ssh_tunnel(&remote).unwrap_or_else(|error| {
        startup_error(
            "Could not connect to remote Apiary",
            format!("{}: {error}", remote.ssh_target),
            1,
        )
    });
    let discovery = state_home_discovery_path(&home);
    write_discovery(
        &discovery,
        remote.local_port,
        None,
        Some(&remote.ssh_target),
    );
    let target = percent_encode_query(&remote.ssh_target);
    let url = format!("http://127.0.0.1:{}/?remote={target}", remote.local_port);
    run_window(url, false, home, bootstrap);
    let _ = std::fs::remove_file(discovery);
    let _ = tunnel.child.kill();
}

fn run_window(
    mut url: String,
    local_folder_picker: bool,
    home: PathBuf,
    bootstrap: DesktopBootstrap,
) {
    let bootstrap_json = serde_json::to_string(&bootstrap).expect("serialize desktop bootstrap");
    url.push_str("#desktop=");
    url.push_str(&percent_encode_query(&bootstrap_json));
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            // The cockpit's "Choose…" buttons ask the daemon, which asks us
            // for the native folder dialog (called from a blocking task,
            // never the main thread).
            if local_folder_picker {
                let handle = app.handle().clone();
                apiary_hostd::ops::set_folder_picker(Box::new(move || {
                    use tauri_plugin_dialog::DialogExt;
                    handle
                        .dialog()
                        .file()
                        .blocking_pick_folder()
                        .map(|p| p.to_string())
                }));
            }
            let handle = app.handle().clone();
            let navigation_home = home.clone();
            let allowed_url: tauri::Url = url.parse().expect("boot url");
            let allowed_port = allowed_url.port();
            tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::External(allowed_url))
                .on_navigation(move |next| {
                    if next.scheme() == "apiary-desktop" {
                        handle_desktop_navigation(&handle, &navigation_home, next);
                        return false;
                    }
                    next.scheme() == "http"
                        && next.host_str() == Some("127.0.0.1")
                        && next.port() == allowed_port
                })
                .title("Apiary")
                .inner_size(1360.0, 900.0)
                .min_inner_size(720.0, 520.0)
                .build()?;
            Ok(())
        })
        .run(app_context())
        .expect("apiary desktop");
}

fn startup_error(title: &str, message: impl Into<String>, code: i32) -> ! {
    let title = title.to_string();
    let message = message.into();
    eprintln!("Apiary: {title}: {message}");
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
            let handle = app.handle().clone();
            app.dialog()
                .message(message)
                .title(title)
                .kind(MessageDialogKind::Error)
                .show(move |_| handle.exit(code));
            Ok(())
        })
        .run(app_context());
    if let Err(error) = result {
        eprintln!("Apiary could not show its startup error: {error}");
    }
    std::process::exit(code)
}

fn app_context() -> tauri::Context<tauri::Wry> {
    tauri::generate_context!()
}

fn state_home_discovery_path(home: &std::path::Path) -> PathBuf {
    home.join("desktop.json")
}

fn write_discovery(path: &std::path::Path, port: u16, token: Option<&str>, remote: Option<&str>) {
    let body = serde_json::json!({
        "url": format!("http://127.0.0.1:{port}"),
        "token": token.unwrap_or(""),
        "pid": std::process::id(),
        "mode": if remote.is_some() { "remote" } else { "local" },
        "remote": remote,
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

fn load_launch_config(home: &Path) -> Result<LaunchConfig, String> {
    if let Ok(target) = std::env::var("APIARY_REMOTE_SSH") {
        if target.trim().is_empty() {
            return Err("APIARY_REMOTE_SSH must not be empty".into());
        }
        let parse_port = |name: &str, default: u16| -> Result<u16, String> {
            match std::env::var(name) {
                Ok(value) => value
                    .parse::<u16>()
                    .map_err(|_| format!("{name} must be a port from 1 to 65535")),
                Err(_) => Ok(default),
            }
        };
        let remote_port = parse_port("APIARY_REMOTE_PORT", default_remote_port())?;
        let local_port = parse_port("APIARY_REMOTE_LOCAL_PORT", remote_port)?;
        let ssh_port = std::env::var("APIARY_REMOTE_SSH_PORT")
            .ok()
            .map(|value| {
                value.parse::<u16>().map_err(|_| {
                    "APIARY_REMOTE_SSH_PORT must be a port from 1 to 65535".to_string()
                })
            })
            .transpose()?;
        let remote = RemoteConfig {
            ssh_target: target,
            ssh_port,
            remote_port,
            local_port,
            identity_file: std::env::var_os("APIARY_REMOTE_IDENTITY").map(PathBuf::from),
        };
        validate_remote(&remote)?;
        return Ok(LaunchConfig {
            remote: Some(remote.clone()),
            bootstrap: DesktopBootstrap {
                mode: DesktopMode::Remote,
                active_remote: Some("environment".into()),
                remotes: vec![DesktopRemoteView {
                    id: "environment".into(),
                    name: remote.ssh_target.clone(),
                    ssh_target: remote.ssh_target.clone(),
                }],
                environment_override: true,
            },
        });
    }

    let (config, remote) = normalize_desktop_config(read_desktop_config(home)?)?;
    Ok(LaunchConfig {
        remote,
        bootstrap: DesktopBootstrap {
            mode: config.mode,
            active_remote: config.active_remote,
            remotes: config
                .remotes
                .into_iter()
                .map(|saved| DesktopRemoteView {
                    id: saved.id,
                    name: saved.name,
                    ssh_target: saved.remote.ssh_target,
                })
                .collect(),
            environment_override: false,
        },
    })
}

fn read_desktop_config(home: &Path) -> Result<DesktopConfig, String> {
    let path = home.join("desktop-config.json");
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DesktopConfig::default())
        }
        Err(error) => return Err(format!("could not read {}: {error}", path.display())),
    };
    serde_json::from_str(&raw).map_err(|error| format!("{} is invalid: {error}", path.display()))
}

fn normalize_desktop_config(
    mut config: DesktopConfig,
) -> Result<(DesktopConfig, Option<RemoteConfig>), String> {
    let mut ids = std::collections::HashSet::new();
    for saved in &config.remotes {
        validate_saved_remote(saved)?;
        if !ids.insert(saved.id.clone()) {
            return Err(format!("remote profile id {:?} is duplicated", saved.id));
        }
    }

    if let Some(legacy) = config.remote.clone() {
        validate_remote(&legacy)?;
        if let Some(saved) = config.remotes.iter().find(|saved| saved.remote == legacy) {
            if config.mode == DesktopMode::Remote && config.active_remote.is_none() {
                config.active_remote = Some(saved.id.clone());
            }
        } else {
            let id = unique_profile_id("remote", &ids);
            ids.insert(id.clone());
            config.remotes.push(SavedRemote {
                id: id.clone(),
                name: legacy.ssh_target.clone(),
                remote: legacy,
            });
            if config.mode == DesktopMode::Remote && config.active_remote.is_none() {
                config.active_remote = Some(id);
            }
        }
    }

    let remote = match config.mode {
        DesktopMode::Local => None,
        DesktopMode::Remote => {
            if let Some(active) = config.active_remote.as_deref() {
                Some(
                    config
                        .remotes
                        .iter()
                        .find(|saved| saved.id == active)
                        .ok_or_else(|| format!("active remote profile {active:?} does not exist"))?
                        .remote
                        .clone(),
                )
            } else if let Some(remote) = config.remote.clone() {
                Some(remote)
            } else {
                return Err("remote mode requires an active remote profile".into());
            }
        }
    };
    Ok((config, remote))
}

fn validate_saved_remote(saved: &SavedRemote) -> Result<(), String> {
    if saved.id.is_empty()
        || saved.id.len() > 64
        || !saved
            .id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(
            "remote profile ids may contain only letters, numbers, hyphens, and underscores".into(),
        );
    }
    let name = saved.name.trim();
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err("remote profile names must be from 1 to 80 printable characters".into());
    }
    validate_remote(&saved.remote)
}

fn unique_profile_id(seed: &str, existing: &std::collections::HashSet<String>) -> String {
    let mut base = seed
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    base.truncate(48);
    if base.is_empty() {
        base = "remote".into();
    }
    if !existing.contains(&base) {
        return base;
    }
    for suffix in 2..=9999 {
        let candidate = format!("{base}-{suffix}");
        if !existing.contains(&candidate) {
            return candidate;
        }
    }
    format!("remote-{}", std::process::id())
}

fn handle_desktop_navigation(handle: &tauri::AppHandle, home: &Path, url: &tauri::Url) {
    let pending = match pending_desktop_action(home, url) {
        Ok(pending) => pending,
        Err(error) => {
            handle
                .dialog()
                .message(error)
                .title("Backend change refused")
                .kind(MessageDialogKind::Error)
                .show(|_| {});
            return;
        }
    };
    let restart_handle = handle.clone();
    let error_handle = handle.clone();
    let home = home.to_path_buf();
    handle
        .dialog()
        .message(pending.message)
        .title(pending.title)
        .kind(MessageDialogKind::Info)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Restart Apiary".into(),
            "Cancel".into(),
        ))
        .show(move |confirmed| {
            if !confirmed {
                return;
            }
            if let Some(config) = pending.config {
                if let Err(error) = write_desktop_config(&home, &config) {
                    error_handle
                        .dialog()
                        .message(error)
                        .title("Could not save backend")
                        .kind(MessageDialogKind::Error)
                        .show(|_| {});
                    return;
                }
            }
            restart_handle.request_restart();
        });
}

fn pending_desktop_action(home: &Path, url: &tauri::Url) -> Result<PendingDesktopAction, String> {
    if std::env::var_os("APIARY_REMOTE_SSH").is_some() {
        return Err(
            "This backend is controlled by APIARY_REMOTE_SSH. Remove that environment override before switching in the app."
                .into(),
        );
    }
    let action = url.host_str().unwrap_or_default();
    let (mut config, _) = normalize_desktop_config(read_desktop_config(home)?)?;
    match action {
        "switch" => {
            let profile = desktop_param(url, "profile")?;
            if profile == "local" {
                config.mode = DesktopMode::Local;
                config.active_remote = None;
                config.remote = None;
                Ok(PendingDesktopAction {
                    title: "Use Apiary on this Mac?".into(),
                    message:
                        "Apiary will restart and use the agents and settings stored on this Mac."
                            .into(),
                    config: Some(config),
                })
            } else {
                let saved = config
                    .remotes
                    .iter()
                    .find(|saved| saved.id == profile)
                    .ok_or_else(|| "that saved backend no longer exists".to_string())?
                    .clone();
                config.mode = DesktopMode::Remote;
                config.active_remote = Some(saved.id.clone());
                config.remote = Some(saved.remote.clone());
                Ok(PendingDesktopAction {
                    title: format!("Connect to {}?", saved.name),
                    message: format!(
                        "Apiary will restart and connect to {} over SSH.",
                        saved.remote.ssh_target
                    ),
                    config: Some(config),
                })
            }
        }
        "reconnect" => Ok(PendingDesktopAction {
            title: "Reconnect to this backend?".into(),
            message: "Apiary will restart the current local host or SSH connection.".into(),
            config: None,
        }),
        "add" => {
            let name = desktop_param(url, "name")?;
            let target = desktop_param(url, "ssh_target")?;
            let remote = RemoteConfig {
                ssh_target: target,
                ssh_port: optional_port_param(url, "ssh_port")?,
                remote_port: port_param(url, "remote_port", default_remote_port())?,
                local_port: port_param(url, "local_port", default_remote_port())?,
                identity_file: optional_path_param(url, "identity_file")?,
            };
            let existing = config
                .remotes
                .iter()
                .map(|saved| saved.id.clone())
                .collect::<std::collections::HashSet<_>>();
            let saved = SavedRemote {
                id: unique_profile_id(&name, &existing),
                name,
                remote,
            };
            validate_saved_remote(&saved)?;
            config.mode = DesktopMode::Remote;
            config.active_remote = Some(saved.id.clone());
            config.remote = Some(saved.remote.clone());
            config.remotes.push(saved.clone());
            Ok(PendingDesktopAction {
                title: format!("Add and connect to {}?", saved.name),
                message: format!(
                    "Apiary will save this backend, restart, and connect to {} over SSH.",
                    saved.remote.ssh_target
                ),
                config: Some(config),
            })
        }
        "remove" => {
            let profile = desktop_param(url, "profile")?;
            let index = config
                .remotes
                .iter()
                .position(|saved| saved.id == profile)
                .ok_or_else(|| "that saved backend no longer exists".to_string())?;
            let removed = config.remotes.remove(index);
            if config.active_remote.as_deref() == Some(&profile) {
                config.mode = DesktopMode::Local;
                config.active_remote = None;
                config.remote = None;
            }
            Ok(PendingDesktopAction {
                title: format!("Remove {}?", removed.name),
                message: "The saved connection will be removed and Apiary will restart. Data on the remote server will not be changed."
                    .into(),
                config: Some(config),
            })
        }
        _ => Err("unknown desktop backend action".into()),
    }
}

fn desktop_param(url: &tauri::Url, name: &str) -> Result<String, String> {
    let value = url
        .query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
        .unwrap_or_default();
    let value = value.trim().to_string();
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        return Err(format!("{name} is missing or invalid"));
    }
    Ok(value)
}

fn optional_port_param(url: &tauri::Url, name: &str) -> Result<Option<u16>, String> {
    let value = url
        .query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
        .unwrap_or_default();
    if value.trim().is_empty() {
        return Ok(None);
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .map(Some)
        .ok_or_else(|| format!("{name} must be a port from 1 to 65535"))
}

fn port_param(url: &tauri::Url, name: &str, default: u16) -> Result<u16, String> {
    Ok(optional_port_param(url, name)?.unwrap_or(default))
}

fn optional_path_param(url: &tauri::Url, name: &str) -> Result<Option<PathBuf>, String> {
    let value = url
        .query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
        .unwrap_or_default();
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(value);
    if value.len() > 1024 || value.chars().any(char::is_control) || !path.is_absolute() {
        return Err(format!("{name} must be an absolute path"));
    }
    Ok(Some(path))
}

fn write_desktop_config(home: &Path, config: &DesktopConfig) -> Result<(), String> {
    std::fs::create_dir_all(home)
        .map_err(|error| format!("could not create {}: {error}", home.display()))?;
    let path = home.join("desktop-config.json");
    let temporary = home.join(format!(".desktop-config.json.{}.tmp", std::process::id()));
    let body = serde_json::to_vec_pretty(config)
        .map_err(|error| format!("could not serialize backend settings: {error}"))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("could not create {}: {error}", temporary.display()))?;
    if let Err(error) = file.write_all(&body).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("could not write {}: {error}", temporary.display()));
    }
    std::fs::rename(&temporary, &path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        format!("could not replace {}: {error}", path.display())
    })?;
    Ok(())
}

fn validate_remote(remote: &RemoteConfig) -> Result<(), String> {
    let target = remote.ssh_target.trim();
    if target.is_empty()
        || target.starts_with('-')
        || target.chars().any(char::is_whitespace)
        || target.chars().any(char::is_control)
    {
        return Err(
            "remote.ssh_target must be a single SSH destination such as user@server".into(),
        );
    }
    if remote.remote_port == 0 || remote.local_port == 0 || remote.ssh_port == Some(0) {
        return Err("remote ports must be from 1 to 65535".into());
    }
    Ok(())
}

fn ssh_args(remote: &RemoteConfig) -> Vec<String> {
    let mut args = vec![
        "-N".into(),
        "-T".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
    ];
    if let Some(port) = remote.ssh_port {
        args.extend(["-p".into(), port.to_string()]);
    }
    if let Some(identity) = remote.identity_file.as_ref() {
        args.extend(["-i".into(), identity.to_string_lossy().into_owned()]);
    }
    args.extend([
        "-L".into(),
        format!(
            "127.0.0.1:{}:127.0.0.1:{}",
            remote.local_port, remote.remote_port
        ),
        remote.ssh_target.clone(),
    ]);
    args
}

fn start_ssh_tunnel(remote: &RemoteConfig) -> Result<SshTunnel, String> {
    TcpListener::bind(("127.0.0.1", remote.local_port)).map_err(|error| {
        format!(
            "local port {} is unavailable ({error}); stop the local Apiary host or choose another local_port",
            remote.local_port
        )
    })?;
    let mut child = Command::new("ssh")
        .args(ssh_args(remote))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not launch the system ssh client: {error}"))?;

    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("could not inspect ssh: {error}"))?
        {
            let mut details = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_string(&mut details);
            }
            let details = details.trim();
            return Err(if details.is_empty() {
                format!("ssh exited with {status}")
            } else {
                details.to_string()
            });
        }
        if remote_host_ready(remote.local_port) {
            return Ok(SshTunnel { child });
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(
                "timed out waiting for the SSH tunnel; verify the host, key, and remote daemon"
                    .into(),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn remote_host_ready(port: u16) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(300)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    if stream
        .write_all(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response).is_ok()
        && (response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200"))
        && response.contains("\"ok\":true")
}

fn percent_encode_query(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote() -> RemoteConfig {
        RemoteConfig {
            ssh_target: "apiary@example.com".into(),
            ssh_port: Some(2222),
            remote_port: 7777,
            local_port: 7777,
            identity_file: Some(PathBuf::from("/tmp/apiary key")),
        }
    }

    #[test]
    fn rejects_ssh_option_instead_of_destination() {
        let mut config = remote();
        config.ssh_target = "-oProxyCommand=evil".into();
        assert!(validate_remote(&config).is_err());
    }

    #[test]
    fn ssh_tunnel_is_loopback_only_and_noninteractive() {
        let args = ssh_args(&remote());
        assert!(args.iter().any(|arg| arg == "BatchMode=yes"));
        assert!(args.iter().any(|arg| arg == "StrictHostKeyChecking=yes"));
        assert!(args
            .iter()
            .any(|arg| arg == "127.0.0.1:7777:127.0.0.1:7777"));
        assert_eq!(args.last().map(String::as_str), Some("apiary@example.com"));
    }

    #[test]
    fn remote_label_is_safe_in_a_query_string() {
        assert_eq!(percent_encode_query("me@host name"), "me%40host%20name");
    }

    #[test]
    fn config_defaults_to_matching_oauth_ports() {
        let config: DesktopConfig = serde_json::from_str(
            r#"{"mode":"remote","remote":{"ssh_target":"apiary@example.com"}}"#,
        )
        .unwrap();
        let remote = config.remote.unwrap();
        assert_eq!(remote.remote_port, 7777);
        assert_eq!(remote.local_port, 7777);
    }

    #[test]
    fn legacy_remote_becomes_an_active_saved_profile() {
        let config: DesktopConfig = serde_json::from_str(
            r#"{"mode":"remote","remote":{"ssh_target":"apiary@example.com"}}"#,
        )
        .unwrap();
        let (normalized, selected) = normalize_desktop_config(config).unwrap();
        assert_eq!(normalized.active_remote.as_deref(), Some("remote"));
        assert_eq!(normalized.remotes.len(), 1);
        assert_eq!(normalized.remotes[0].name, "apiary@example.com");
        assert_eq!(selected.unwrap().ssh_target, "apiary@example.com");
    }

    #[test]
    fn saved_profiles_round_trip_in_the_desktop_config() {
        let config = DesktopConfig {
            mode: DesktopMode::Remote,
            remote: Some(remote()),
            active_remote: Some("home-server".into()),
            remotes: vec![SavedRemote {
                id: "home-server".into(),
                name: "Home server".into(),
                remote: remote(),
            }],
        };
        let encoded = serde_json::to_string(&config).unwrap();
        let decoded: DesktopConfig = serde_json::from_str(&encoded).unwrap();
        let (normalized, selected) = normalize_desktop_config(decoded).unwrap();
        assert_eq!(normalized.active_remote.as_deref(), Some("home-server"));
        assert_eq!(normalized.remotes.len(), 1);
        assert_eq!(selected, Some(remote()));
    }

    #[test]
    fn duplicate_profile_names_get_stable_unique_ids() {
        let existing = ["home-server".to_string()]
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique_profile_id("Home server", &existing), "home-server-2");
    }

    #[test]
    fn backend_actions_reject_relative_identity_paths() {
        let url = tauri::Url::parse(
            "apiary-desktop://add?name=Server&ssh_target=apiary%40example.com&identity_file=.ssh%2Fkey",
        )
        .unwrap();
        assert!(optional_path_param(&url, "identity_file").is_err());
    }
}
