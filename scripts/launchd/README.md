# Running Apiary as launchd agents (macOS)

Three user agents cover desktop, speech, and headless deployments. Install only
the services a machine needs:

- `wine.wisco.apiary.desktop` — the desktop app (embedded daemon +
  supervisor: presence, routines, lease). `KeepAlive` restarts it if it
  dies. The first GUI unlock can remember the keystore passphrase in macOS
  Keychain; the launchd plist never contains it. (NIP-46 remote signing is
  still on the roadmap.)
- `wine.wisco.apiary.kokoro` — the local TTS server (`services/kokoro`).
- `wine.wisco.apiary.hostd` — the headless host for SSH remote mode. It binds
  only `127.0.0.1:7777`; the Desktop app supplies the encrypted tunnel.

Install:

```bash
sed "s#\$HOME#$HOME#g" scripts/launchd/wine.wisco.apiary.desktop.plist.template > ~/Library/LaunchAgents/wine.wisco.apiary.desktop.plist
sed "s#\$HOME#$HOME#g" scripts/launchd/wine.wisco.apiary.kokoro.plist.template > ~/Library/LaunchAgents/wine.wisco.apiary.kokoro.plist
sed "s#\$HOME#$HOME#g" scripts/launchd/wine.wisco.apiary.hostd.plist.template > ~/Library/LaunchAgents/wine.wisco.apiary.hostd.plist
chmod 600 ~/Library/LaunchAgents/wine.wisco.apiary.{desktop,kokoro,hostd}.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/wine.wisco.apiary.kokoro.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/wine.wisco.apiary.desktop.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/wine.wisco.apiary.hostd.plist
```

Logs: `~/.apiary/logs/{desktop,kokoro,hostd}.log`. Restart a service after a
rebuild with `launchctl kickstart -k gui/$(id -u)/wine.wisco.apiary.<service>`.

Inference API keys belong sealed in the agent's manifest (Inference tab /
`apiary credential seal`), not in the launch environment. Claude Code
routes use the host's existing `claude auth login` session. Apiary disables
Claude Code's own tools and dispatches only the connectors granted to the
agent. A relaunch retrieves the keystore passphrase from macOS Keychain when
automatic unlock has been enabled in the cockpit.
