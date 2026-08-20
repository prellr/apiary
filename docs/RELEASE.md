# Release checklist

Apiary releases fail closed. A successful compilation is not sufficient for a
release because the product holds identities, credentials, and remote-control
authority.

## 1. Source gate

- The release commit is on a reviewed pull request, not a developer branch.
- CI formatting, clippy, builds, tests, and `cargo audit` are green.
- `main` requires the CI checks and review before merge.
- `CHANGELOG.md` names user-visible changes and known limitations.
- Package versions, lockfile, and repository metadata are correct.

Run the local equivalent:

```bash
cargo fmt --all --check
cargo clippy --workspace --exclude apiary-desktop --all-targets -- -D warnings
cargo clippy -p apiary-desktop --all-targets -- -D warnings
cargo build --workspace --exclude apiary-desktop
cargo test --workspace --exclude apiary-desktop
cargo build -p apiary-desktop
cargo test -p apiary-desktop
cargo audit
```

## 2. Remote security gate

- Purge assets cached before the private-cockpit boundary was introduced.
- An unauthenticated request receives only the minimal sign-in page.
- `/app.js` and all APIs are unavailable without an authorized session.
- Host managers, per-agent roles, unassigned identities, expiry, logout, and
  revoked access have been tested against the public origin.
- Cloudflare and browser inspection show `Cache-Control: no-store` on cockpit
  and API responses; no authenticated response is shared from cache.
- Edge and host request limits are enabled and documented.

## 3. macOS artifact gate

Install Tauri CLI 2 once:

```bash
cargo install tauri-cli --version '^2' --locked
```

Provide a Developer ID Application identity through the login keychain or
`APPLE_SIGNING_IDENTITY`. Provide one of Tauri's notarization credential sets:

- `APPLE_API_ISSUER`, `APPLE_API_KEY`, and `APPLE_API_KEY_PATH`; or
- `APPLE_ID`, `APPLE_PASSWORD`, and `APPLE_TEAM_ID`.

Then run:

```bash
scripts/package-macos.sh
```

The manual **Package macOS release candidate** GitHub workflow runs the same
script in the protected `release` environment. Configure its certificate,
keychain, and Apple notarization secrets before using it.

The script produces and validates:

- `target/release/bundle/macos/Apiary.app`
- `target/release/bundle/dmg/Apiary_<version>_<arch>.dmg`
- a sibling `.sha256` checksum

`APIARY_SKIP_NOTARIZATION=1` is permitted only for a local packaging test. It
must never be used for a published artifact.

Test the notarized DMG on a clean supported Mac: download through a browser,
verify Gatekeeper accepts it, install into Applications, complete first setup,
quit and relaunch, connect to a remote host, upgrade over the previous release,
and verify uninstall instructions leave user data untouched unless requested.

## 4. Recovery and operations gate

- Complete the drill in [RECOVERY.md](RECOVERY.md) using release artifacts.
- Verify the restored agent identity, ratification, signed log, connectors,
  inference routes, and inactive-by-default state before activation.
- Verify rollback to the prior app version does not corrupt current state.
- Confirm health checks, log rotation, restart policy, and alerts on the public
  host.

The host exposes minimal unauthenticated probes at `/healthz` and `/readyz`.
They deliberately omit version, paths, agents, and authentication details.
`/readyz` refuses a NIP-98 host until at least one host manager is configured.

## 5. Release approval

- Security review findings classified as critical or high are resolved.
- Privacy, data-retention, support, and known-limitations text matches reality.
- Voice, web search, subscription inference, and third-party harnesses are
  either tested in the compatibility matrix or clearly marked experimental.
- Create the signed tag only after every preceding gate passes.
