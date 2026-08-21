//! Add a governor to a remote Apiary agent and ratify the resulting amendment
//! with a locally recovered human key. The Nostr secret is read directly from
//! macOS Keychain and is never rendered or sent to the remote host.

#[cfg(not(target_os = "macos"))]
compile_error!("this governance utility is available only on macOS");

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use nostr::prelude::*;
use reqwest::blocking::{Client, Response};
use security_framework::passwords::get_generic_password;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const RECOVERY_SERVICE: &str = "wine.wisco.apiary.recovered-nostr-key";
const NIP98_KIND: u16 = 27235;

fn main() -> Result<(), String> {
    let mut args = std::env::args();
    let _program = args.next();
    let origin = args.next().ok_or_else(usage)?;
    let agent = args.next().ok_or_else(usage)?;
    let current_governor = args.next().ok_or_else(usage)?;
    let additional_governor = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }

    let secret = Zeroizing::new(
        get_generic_password(RECOVERY_SERVICE, &current_governor)
            .map_err(|error| format!("could not read the recovered governor key: {error}"))?,
    );
    let secret_text = Zeroizing::new(
        String::from_utf8(secret.to_vec())
            .map_err(|_| "the recovered governor key is not valid UTF-8".to_string())?,
    );
    let keys = Keys::parse(secret_text.as_str())
        .map_err(|error| format!("could not parse the recovered governor key: {error}"))?;
    let actual =
        apiary_core::identity::to_npub(&keys.public_key()).map_err(|error| error.to_string())?;
    if actual != current_governor {
        return Err("the recovered key does not match the current governor".into());
    }

    let client = Client::builder()
        .build()
        .map_err(|error| format!("could not create the HTTP client: {error}"))?;
    let origin = origin.trim_end_matches('/');

    let governors_path = format!("/api/agents/{agent}/governors");
    let governors_body = json!({
        "npubs": [current_governor, additional_governor]
    })
    .to_string();
    let governors = post(&client, &keys, origin, &governors_path, &governors_body)?;
    require_ok("governor amendment", &governors)?;

    let export_path = format!("/api/agents/{agent}/ratify/export");
    let export_body = json!({"as": actual}).to_string();
    let exported = post(&client, &keys, origin, &export_path, &export_body)?;
    require_ok("ratification export", &exported)?;
    let unsigned_value = exported
        .get("unsigned_event")
        .cloned()
        .ok_or_else(|| "ratification export omitted unsigned_event".to_string())?;
    let unsigned = UnsignedEvent::from_json(unsigned_value.to_string())
        .map_err(|error| format!("could not parse the unsigned ratification: {error}"))?;
    if unsigned.pubkey != keys.public_key() {
        return Err("the ratification was prepared for a different governor".into());
    }
    let signed = unsigned
        .finalize(&keys)
        .map_err(|error| format!("could not sign the ratification: {error}"))?;

    let import_path = format!("/api/agents/{agent}/ratify/import");
    let signed_value: Value = serde_json::from_str(&signed.as_json())
        .map_err(|error| format!("could not serialize the signed ratification: {error}"))?;
    let import_body = json!({"event": signed_value}).to_string();
    let imported = post(&client, &keys, origin, &import_path, &import_body)?;
    require_ok("ratification import", &imported)?;

    println!("Remote governance amendment ratified");
    println!("agent: {agent}");
    println!("retained governor: {current_governor}");
    println!("added governor: {additional_governor}");
    Ok(())
}

fn usage() -> String {
    "usage: govern_remote_agent <origin> <agent-npub> <current-governor-npub> <additional-governor-npub>".into()
}

fn post(
    client: &Client,
    keys: &Keys,
    origin: &str,
    path: &str,
    body: &str,
) -> Result<Value, String> {
    let url = format!("{origin}{path}");
    let authorization = nip98_authorization(keys, &url, "POST", body.as_bytes())?;
    let response = client
        .post(&url)
        .header("authorization", authorization)
        .header("content-type", "application/json")
        .body(body.to_owned())
        .send()
        .map_err(|error| format!("request to {path} failed: {error}"))?;
    response_json(path, response)
}

fn nip98_authorization(
    keys: &Keys,
    url: &str,
    method: &str,
    body: &[u8],
) -> Result<String, String> {
    let event = EventBuilder::new(Kind::Custom(NIP98_KIND), "")
        .tag(Tag::custom("u", vec![url.to_string()]))
        .tag(Tag::custom("method", vec![method.to_string()]))
        .tag(Tag::custom(
            "payload",
            vec![format!("{:x}", Sha256::digest(body))],
        ))
        .finalize(keys)
        .map_err(|error| format!("could not sign the NIP-98 request: {error}"))?;
    Ok(format!("Nostr {}", BASE64.encode(event.as_json())))
}

fn response_json(path: &str, response: Response) -> Result<Value, String> {
    let status = response.status();
    let text = response
        .text()
        .map_err(|error| format!("could not read the response from {path}: {error}"))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("{path} returned {status} with invalid JSON: {error}"))?;
    if !status.is_success() {
        return Err(format!("{path} returned {status}: {value}"));
    }
    Ok(value)
}

fn require_ok(operation: &str, value: &Value) -> Result<(), String> {
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(format!("{operation} did not report success: {value}"))
    }
}
