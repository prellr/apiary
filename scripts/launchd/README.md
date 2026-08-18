# Running Apiary as launchd agents (macOS)

Two user agents keep the host up across logins and restarts:

- `wine.wisco.apiary.desktop` — the desktop app (embedded daemon +
  supervisor: presence, routines, lease). `KeepAlive` restarts it if it
  dies. It needs the keystore passphrase to unlock at boot; the plist holds
  it, so **the plist must be mode 0600** — same trust boundary as the
  keystore. (Better still: NIP-46 remote signing, on the roadmap.)
- `wine.wisco.apiary.kokoro` — the local TTS server (`services/kokoro`).

Install:

```bash
sed "s/YOUR-KEYSTORE-PASSPHRASE/…/; s#\$HOME#$HOME#g" scripts/launchd/wine.wisco.apiary.desktop.plist.template > ~/Library/LaunchAgents/wine.wisco.apiary.desktop.plist
sed "s#\$HOME#$HOME#g" scripts/launchd/wine.wisco.apiary.kokoro.plist.template > ~/Library/LaunchAgents/wine.wisco.apiary.kokoro.plist
chmod 600 ~/Library/LaunchAgents/wine.wisco.apiary.desktop.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/wine.wisco.apiary.kokoro.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/wine.wisco.apiary.desktop.plist
```

Logs: `~/.apiary/logs/{desktop,kokoro}.log`. Restart after a rebuild:
`launchctl kickstart -k gui/$(id -u)/wine.wisco.apiary.desktop`.

Inference API keys belong sealed in the agent's manifest (Inference tab /
`apiary credential seal`), not in the launch environment. Claude Code
subscription sources use the host's existing `claude auth login` session; an
optional sealed setup token is supported for headless hosts. Apiary disables
Claude Code's own tools and dispatches only the connectors granted to the
agent. A relaunch otherwise needs nothing but the keystore passphrase.
