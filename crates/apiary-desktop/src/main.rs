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
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const KEYCHAIN_SERVICE: &str = "wine.wisco.apiary.keystore";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopConfig {
    #[serde(default)]
    mode: DesktopMode,
    remote: Option<RemoteConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum DesktopMode {
    #[default]
    Local,
    Remote,
}

#[derive(Clone, Debug, Deserialize)]
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
    match load_remote_config(&home) {
        Ok(Some(remote)) => run_remote(home, remote),
        Ok(None) => run_local(home),
        Err(error) => startup_error("Remote configuration error", error, 2),
    }
}

fn run_local(home: PathBuf) {
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
    write_discovery(&discovery, port, Some(&token), None);
    let discovery_for_exit = discovery.clone();

    let url = format!("http://127.0.0.1:{port}/?token={token}");
    run_window(url, true);
    let _ = std::fs::remove_file(discovery_for_exit);
}

fn run_remote(home: PathBuf, remote: RemoteConfig) {
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
    run_window(url, false);
    let _ = std::fs::remove_file(discovery);
    let _ = tunnel.child.kill();
}

fn run_window(url: String, local_folder_picker: bool) {
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

fn load_remote_config(home: &std::path::Path) -> Result<Option<RemoteConfig>, String> {
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
        return Ok(Some(remote));
    }

    let path = home.join("desktop-config.json");
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not read {}: {error}", path.display())),
    };
    let config: DesktopConfig = serde_json::from_str(&raw)
        .map_err(|error| format!("{} is invalid: {error}", path.display()))?;
    match config.mode {
        DesktopMode::Local => Ok(None),
        DesktopMode::Remote => {
            let remote = config.remote.ok_or_else(|| {
                format!(
                    "{} selects remote mode but has no remote object",
                    path.display()
                )
            })?;
            validate_remote(&remote)?;
            Ok(Some(remote))
        }
    }
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
}
