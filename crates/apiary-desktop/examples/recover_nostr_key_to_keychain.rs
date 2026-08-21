//! Recover one locally held Apiary identity into macOS Keychain without ever
//! rendering its plaintext Nostr secret in a terminal or browser.

#[cfg(not(target_os = "macos"))]
compile_error!("this recovery utility is available only on macOS");

use apiary_core::keystore::Keystore;
use nostr::prelude::ToBech32;
use security_framework::passwords::{get_generic_password, set_generic_password};
use std::path::PathBuf;
use zeroize::Zeroizing;

const WORKSPACE_SERVICE: &str = "wine.wisco.apiary.keystore";
const RECOVERY_SERVICE: &str = "wine.wisco.apiary.recovered-nostr-key";

fn main() -> Result<(), String> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let home =
        PathBuf::from(args.next().ok_or_else(|| {
            "usage: recover_nostr_key_to_keychain <apiary-home> <npub>".to_string()
        })?);
    let npub = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "the npub is required and must be valid UTF-8".to_string())?;
    if args.next().is_some() {
        return Err("unexpected extra arguments".into());
    }

    let account = home.to_string_lossy();
    let passphrase_bytes = Zeroizing::new(
        get_generic_password(WORKSPACE_SERVICE, account.as_ref())
            .map_err(|error| format!("could not read the Apiary workspace password: {error}"))?,
    );
    let passphrase = Zeroizing::new(
        String::from_utf8(passphrase_bytes.to_vec())
            .map_err(|_| "the saved workspace password is not valid UTF-8".to_string())?,
    );

    let keystore = Keystore::open(&home).map_err(|error| error.to_string())?;
    let keys = keystore
        .load(&npub, passphrase.as_str())
        .map_err(|error| format!("could not recover that identity: {error}"))?;
    let actual =
        apiary_core::identity::to_npub(&keys.public_key()).map_err(|error| error.to_string())?;
    if actual != npub {
        return Err("the recovered private key does not match the requested npub".into());
    }

    let nsec = Zeroizing::new(
        keys.secret_key()
            .to_bech32()
            .map_err(|error| format!("could not encode the recovered private key: {error}"))?,
    );
    set_generic_password(RECOVERY_SERVICE, &npub, nsec.as_bytes())
        .map_err(|error| format!("could not save the recovered private key: {error}"))?;

    let saved = Zeroizing::new(
        get_generic_password(RECOVERY_SERVICE, &npub)
            .map_err(|error| format!("could not verify the recovered Keychain item: {error}"))?,
    );
    if saved.as_slice() != nsec.as_bytes() {
        return Err("the recovered Keychain item did not verify".into());
    }

    println!("Recovered identity stored in macOS Keychain");
    println!("service: {RECOVERY_SERVICE}");
    println!("account: {npub}");
    Ok(())
}
