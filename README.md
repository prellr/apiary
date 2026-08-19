# Apiary

A host for **portable agents** — durable principals with self-owned cryptographic
identity (nostr), not sessions welded to a platform.

An agent is five things, none of which is the model: **identity** (a nostr
keypair), **constitution** (ratified purpose, role, voice, principles, and
boundaries), **skillset** (ratified SKILL.md workflows), **memory** (signed log
and semantic index), and **permissions** (manifest-declared connectors,
human-owned floors, and encrypted credential grants). The model is rented,
swappable cognition: *inference in, connections out*.

Read the full design: [docs/SPEC.md](docs/SPEC.md).

## Status

Phases 0–3 are complete and live-proven against production infrastructure
(public nostr relays, a production Buzz workspace, real MCP servers, live
model runs). What exists today:

**The substrate** (`apiary-core`)

- Manifest schema v1 — the agent's constitution: identity, operating
  character, skills, inference pool, routing, connectors, memory, presence,
  governance, lease
- Identity: nostr keypair (BIP-340); custody with NIP-44 seal/open,
  per-agent isolation, JIT decrypt, zeroizing buffers
- Dev keystore: NIP-49 (ncryptsec) encrypted keys at rest, 0600/0700 modes
- Signed episodic log: chained nostr events with privacy tiers
  (public / self / local), tamper detection
- Founding ceremony: the agent signs its manifest hash, a human suspend-key
  holder countersigns — both land in the public log. **Unratified agents
  refuse to run**, and any amendment suspends until re-ratified.

**The runtime** (`apiary-runtime`)

- Inference pool: Anthropic (raw Messages API), **OpenAI and xAI** (one
  OpenAI-compatible implementation with function calling; `requires.
  base_url` reaches Groq/Together/llama.cpp/LM Studio/ollama-`/v1`,
  keyless when local), Ollama, mock — slots, not identity; per-slot
  sealed credentials; routing = floors clamp → rules → default,
  resolved host-side
- Spend authority: `tokens_per_day` as a hard ceiling via atomic
  reservations taken before every model call
- Governed run loop: budget → route → hydrate memory (semantic index +
  recency tail) → infer → tool loop → signed checkpoint entries
- Durable role and personality: purpose, role, voice, principles, and
  boundaries are manifest fields injected into every run. Editing them is a
  constitutional amendment that pauses the agent until manager approval
- Portable skills: standard `SKILL.md` frontmatter + Markdown instructions
  import into the ratified manifest. The host selects at most three relevant
  skills per task; unmet connector requirements make a skill visibly
  unavailable and never grant the missing capability
- Provenance framing: memory, tool results, and workspace messages are
  DATA in the working set; instructions come only from the constitution
  and the operator's task (proven live: a channel mention asking an agent
  to use its connectors gets a polite refusal)
- Connectors, default-deny: `nostr-publish` (relay-allowlisted), **`mcp`**
  (see below), read-only **`web-search`** (structured Brave Search results,
  sealed per-agent API key, bounded queries/results, and an optional bundled
  public-page reader), read-only **`web-fetch`** (open known public HTTPS URLs,
  with optional domain restriction and DNS-rebinding/redirect checks), **`files`** (named roots, text-type and
  size limits), read-only **`git`** (status/log/diff/show/search with Git
  hooks and external programs disabled), and **`obsidian` / `markdown-vault`** — named markdown
  knowledge folders (Obsidian vaults, checked-out KB repos, plain note
  dirs) as search/read tools, write only under an explicit cap, every
  path jailed to its vault root. Each grant is a ratified manifest
  amendment with credentials sealed to that agent alone
- Vaults double as **ambient memory**: `memory.vaults` entries are
  chunked (heading-aware) and embedded into the semantic index, so
  retrieval surfaces relevant notes into the working set beside the
  agent's own log memories — as DATA, per the provenance rule. Vault
  content is host-local: it neither exports nor publishes; a destination
  host re-indexes its own copy
- MCP client: revision 2026-07-28 (stateless, per-request `_meta`,
  `server/discover` era probe) with automatic fallback to
  `initialize`-era servers; stdio (scrubbed-env subprocess) and
  Streamable HTTP (mirror headers, `x-mcp-header`, SSE); OAuth grants
  (RFC 9728 → RFC 8414 → PKCE → RFC 9207) with tokens sealed to the agent;
  `caps.allowed_tools` required — the server offers, the manifest decides.
  New MCP entries default to **Read only**, which exposes only tools carrying
  `annotations.readOnlyHint: true`; missing annotations fail closed. Because
  MCP annotations are server-supplied hints, only trusted servers should be
  treated as faithfully classified
- MCP control server at `POST /mcp`: an outside harness can inspect and manage
  Apiary through `apiary_list_agents`, `apiary_get_agent_environment`, and a
  governed REST adapter. Calls authenticate with NIP-98 or a time-bounded
  `Bearer apiary_...` event signed by an Apiary agent's own Nostr identity.
  Every forwarded operation re-enters the ordinary REST router, so target
  governorship and host-manager checks remain authoritative; MCP creates no
  new access. Credential opening, host unlock, agent-key export, UI event
  streams, and folder picking are intentionally not exposed. Calls append a
  local `0600` hash-chained record to `control-audit.jsonl`; request bodies
  and credentials are represented only by hashes
- Foreign harnesses via ACP (proven with claude-code-acp): permission
  requests decided host-side, default deny, harness attribution in the log
- Tiered log publication: public entries publish as-is, self-tier publish
  NIP-44-wrapped to the agent's own key, local never leaves; the remote
  copy is fetched, verified, and decrypted back — portable memory, proven
- **Multi-channel presence**: an agent lives on many platforms at once —
  Buzz (NIP-42, the agent's own key), Telegram (Bot API long poll, sealed
  token, chat allowlist), Slack (Socket Mode, sealed app+bot tokens), and
  anything the community builds via the **Channel Plugin Protocol**
  (`apiary-channel/1`, docs/CHANNEL_PLUGINS.md): plugins are executables
  speaking newline JSON-RPC on stdio, spawned env-scrubbed, handed their
  one sealed credential at initialize. Every mention on every platform
  takes the same governed path (logged, DATA-framed, budgeted); one lease
  spans all of an agent's channels; the supervisor runs, restarts, and
  bounces each channel independently. Alongside MCP (tools) and ACP
  (harnesses), presence plugins complete Apiary's three plugin standards —
  only the last one is ours, because only it had no industry standard
- **Lease**: single-host standing presence via agent-signed replaceable
  relay events; contested starts refuse and name the holder; takeover is
  `contested-human` — a button a person presses; the loser yields within
  one heartbeat interval

- **Native portability**: `agent export` packs manifest + NIP-49-locked
  key + full signed log + semantic index into one verified bundle — ALL
  of the agent's memory travels, recall included. With
  `--export-passphrase`, the traveling key is re-encrypted under a
  disposable handoff secret, so an agent can be GIVEN to someone else:
  your keystore passphrase never travels, and their host re-encrypts
  under their own passphrase on arrival (the key lets them act as the
  agent; amending its constitution still requires a listed suspend key).
  With `--to <npub>`, the whole bundle is SEALED instead: one kind-4602
  event signed by the agent's own key and NIP-44-encrypted to the
  recipient — no secret in flight, tamper- and truncation-evident,
  local-tier memory confidential in transit, safe to send over any
  channel. Three modes, none required: plain / passphrase / sealed; `agent import` refuses
  anything that fails key↔manifest agreement, a signature, the chain, or
  ratification, and arrivals are INACTIVE (the lease referees the
  switchover). `agent recover` rebuilds an agent from its relays alone —
  the manifest publishes as an addressable event (kind 34600) alongside
  the log, so npub + key + passphrase is enough to resurrect the agent
  anywhere (local-tier entries stay home by design; gaps are reported).
  The index is unsigned derived data, so import verifies every row
  against the signed log — a row whose text disagrees with its signed
  entry is dropped, never trusted

**The host** (`apiary-hostd`, `apiary-desktop`)

- One router, three faces: headless daemon, REST/AG-UI API, and the Tauri
  desktop app running it in-process behind a per-launch token
- Supervisor: ACTIVE agents with declared `presence.buzz` get their
  listener started, restarted on death, bounced on manifest amendment,
  stopped on deactivation — and lease-coordinated across hosts
- NIP-98 signed-request auth for remote use; governor-bound authorization
  (the signer must be a suspend key of the agent it touches), and a persistent
  **host manager allowlist** gating host-scoped operations — founding,
  importing, the connector library, lock/unlock — independently of any
  agent's governors. `--admin <npub>` bootstraps the first manager

- **Relay pool**: one supervised worker per relay URL shared by the
  whole process — leases, publication, recovery, and connectors ride
  persistent connections with capped-backoff reconnect and idle
  keepalive, instead of a connection per operation. Pool health is in
  `/api/status`.

Remaining roadmap: NIP-46 remote-signer custody, OS sandbox for ACP
subprocesses, relay delivery of sealed handoffs, log checkpointing.

## Quick start

The fastest path is the desktop app — everything below (and everything the
CLI can do) is operable from the GUI with inline explanations:

```bash
cargo run -p apiary-desktop
```

The desktop can switch between its embedded host and saved headless servers.
Open **Host status**, choose a backend, and select **Switch**. The same menu can
reconnect, remove a saved server, or add an SSH connection. Apiary confirms the
change in a native dialog, restarts, and keeps the headless daemon bound to the
server's loopback interface.

Backend profiles are stored with `0600` permissions in
`~/.apiary/desktop-config.json`. Existing single-server configurations are
adopted as the first saved profile automatically. `APIARY_REMOTE_SSH` and its
related environment settings remain the highest-priority override; while an
override is present, the in-app switcher is read-only.

Or the CLI:

```bash
cargo build

export APIARY_PASSPHRASE=…   # dev-only keystore passphrase (desktop uses macOS Keychain)

# Found an agent (requires a human suspend key — suspension authority
# never rests with the agent's own key)
apiary agent new --name scout --suspend-key npub1…

apiary agent list
apiary manifest validate ~/.apiary/agents/<npub>/manifest.yaml

# Ratify the manifest as the human (constitution, then amendments).
# Nothing runs unratified.
apiary agent ratify <agent-npub> --as <your-npub>

# Run a task. Routing: floors clamp, then rules, then default.
apiary run <agent-npub> --task "Summarize your purpose" --class reasoning

# The track record: signed, chained, verifiable.
apiary log show <agent-npub>
apiary log verify <agent-npub>

# Seal a connector credential to the agent's key (NIP-44)
echo -n "$SECRET" | apiary credential seal <npub>
```

To give an agent a real brain, add an inference slot to its `manifest.yaml`
(provider `anthropic` uses a sealed credential or `ANTHROPIC_API_KEY` /
`ANTHROPIC_AUTH_TOKEN` from the environment; `ollama` runs locally; `mock`
echoes for testing):

```yaml
inference:
  - name: workhorse
    provider: anthropic
    model: claude-opus-5
routing:
  default: workhorse
governance:
  budgets:
    tokens_per_day: 200000
```

State lives in `~/.apiary` (`APIARY_HOME` to override). Never commit it.

## Desktop app (Tauri)

In local mode the desktop app runs the full `apiary-hostd` router in-process on
a loopback port and opens the cockpit in a native window. Remote mode connects
the same cockpit to a headless host over SSH. Tabs, each with inline
explanations:

- **Overview** — identity (with rename), activation switch, governance
  (suspend keys, budget with a live spend meter), inference pool & routing,
  connectors, memory tiers & relays, **live lease state with the
  TAKE OVER button**, listener status that explains itself
- **Run** — governed one-shot tasks with routing class / data class,
  streamed as AG-UI events; every model call lands as a signed checkpoint
- **Log** — chain verification, publish to relays, fetch-and-verify the
  remote copy
- **Manifest** — YAML editor with a field guide, the amend → auto-suspend →
  re-ratify cycle, and external ratification (export the unsigned event,
  sign with your own nostr tooling, import)
- **Buzz** — profile, channel discovery/read/post/join, and the supervised
  mention listener
- **Connectors** — this agent's grants and revokes; definitions live in the
  **host connector library** (sidebar, host-scoped, shows which agents hold
  each entry), with curated setup templates for built-in Web, Files, Git,
  and GitHub, plus advanced MCP servers and OAuth-granted remotes
- **Skills** — import, edit, and remove standard `SKILL.md` workflows;
  requirement status is shown separately from connector grants
- **Credentials** — NIP-44 seal/open against the agent's key
- **Header** — host status chips, keystore lock/unlock (memory for the
  session, with optional macOS Keychain automatic unlock), npub⇄hex key tool

Runtime governance is supervised, not scripted: activate an agent whose
manifest declares `presence.buzz` and the host starts its listener, restarts
it if it dies, bounces it the moment the manifest changes (returning only
once re-ratified), stops it on deactivation, and coordinates with other
hosts through the lease — contested starts refuse and name the holder;
taking over a live agent is always a human act.

Security posture: the embedded daemon binds `127.0.0.1` on an ephemeral port
and requires a per-launch random token that only the app's own webview
receives — other local processes can't drive it. The desktop can retrieve its
keystore passphrase from macOS Keychain; `APIARY_PASSPHRASE` remains a
development/headless option. `ANTHROPIC_API_KEY` in the app's environment
enables anthropic-routed runs and model-drafted foundings.

The plain daemon (`apiary-hostd`) serves the same cockpit at `--bind` for
headless hosts; add `--auth nip98` beyond localhost.

### Remote desktop mode

Apiary Desktop can operate a headless Apiary host over SSH. The daemon stays
bound to the server's loopback interface, SSH supplies encryption and host/user
authentication, and all agent keys, credentials, channels, and inference stay
on the server.

On the server, run the normal headless daemon without exposing its port:

```bash
apiary-hostd --bind 127.0.0.1:7777 --auth open
```

On the Mac, connect to the server once in Terminal so its host key is in
`known_hosts`, then create `~/.apiary/desktop-config.json`:

```json
{
  "mode": "remote",
  "remote": {
    "ssh_target": "apiary@example.com",
    "remote_port": 7777,
    "local_port": 7777
  }
}
```

Launch Apiary normally. It opens a noninteractive, loopback-only SSH tunnel and
labels the cockpit with the connected server. SSH agent keys are used by
default; `ssh_port` and `identity_file` are optional. Set `mode` to `local` (or
remove the file) to return to the embedded host. The same port on each side is
recommended because browser-based OAuth callbacks use the host's canonical
origin. For a one-off remote launch, `APIARY_REMOTE_SSH=user@server` selects
remote mode without a config file. File and vault paths entered in remote mode
refer to the server's filesystem; the Mac folder picker is intentionally off.

Do not bind the headless daemon to a public interface in this mode. Use `open`
auth only when the daemon remains on server loopback and the SSH account plus
trusted processes on both machines form the operator boundary.

### Multiple people and Nostr identities

**People & access** separates two kinds of authority:

- **Host managers** administer the Apiary installation: agents, integrations,
  credentials, and lock state. Add them by public `npub` or hex key. Apiary
  stores only the public identity in `~/.apiary/host-managers.json`; each person
  keeps their private key in their own signer.
- **Agent managers** are the `governance.suspend_keys` on one agent. An entry
  may identify a person or a separate Apiary agent. It can approve, stop, and
  operate that agent without automatically receiving access to the rest of the
  host. An agent can never name its own identity as a manager.

New and existing agents can name multiple people. Each listed person has
independent authority; this is an allowlist, not M-of-N approval. Changing an
agent's managers pauses it until one of the new managers ratifies the amended
configuration. The last persistent host manager cannot be removed, and a
manager supplied by `--admin` remains until the daemon restarts without that
flag. Host-manager Nostr signatures are enforced when the daemon uses
`--auth nip98`; in local desktop and SSH-tunnel `open` mode, the per-launch
token or SSH account remains the request boundary.

### Apiary control MCP

The daemon and desktop host the same stateless MCP endpoint at `/mcp`. It
speaks the current `server/discover` protocol and falls back to the
`2025-06-18` initialize handshake. Its tools are:

- `apiary_describe` — protocol, authorization, route coverage, and exclusions
- `apiary_list_agents` — only agents governed by the authenticated identity
- `apiary_get_agent_environment` — manifest, skills, inference, spend,
  routines, lease, and listener state
- `apiary_request` — `GET`, `POST`, `PUT`, or `DELETE` an allowed `/api/...`
  route through the existing authorization and amendment gates

For a human or external Nostr identity, sign each `POST /mcp` as an ordinary
NIP-98 request. For a hosted manager agent, open that agent in the cockpit,
use **Agent management access → Create MCP access token**, and store the
result only as that agent's sealed MCP bearer credential. The token is an
event signed by the agent, scoped to this Apiary installation's stable host
identity (so a desktop port change does not invalidate it), and
expires after 1–90 days. It identifies the caller but grants nothing by
itself: add the manager agent's npub to each target agent separately.

Example HTTP MCP configuration:

```yaml
transport: http
url: https://apiary.example/mcp
bearer: apiary_<signed-token>
allowed_tools:
  - apiary_describe
  - apiary_list_agents
  - apiary_get_agent_environment
  - apiary_request
```

`apiary_request` deliberately cannot open credential plaintext, unlock the
host, export an agent key bundle, hold the UI event stream, or invoke the
desktop folder picker. Connector credentials remain sealed to their agent.

### Per-agent harness policy

Foreign harnesses are ratified capabilities in `manifest.harnesses[]`, not
commands an operator can inject at run time. Each grant independently chooses:

- `access`: `inference-only`, `curated` ACP permission titles, or the `full`
  native harness tool surface
- `profile`: `isolated` per-agent HOME, `curated` environment inheritance, or
  the complete host `inherit` profile (including its global agents, skills,
  extensions, credentials, and environment)
- `metering`: `strict` refusal while ACP usage is unknown, a fixed
  `estimated` charge, or intentionally `unmetered` operation outside the
  daily token limit
- exact command, arguments, optional working directory, and environment names

Example:

```yaml
harnesses:
  - name: goose-workspace
    kind: acp
    command: goose
    args: [acp]
    access: curated
    profile: isolated
    allowed_tools: [read_file, write_file, shell]
    metering: estimated
    estimated_tokens_per_run: 8192
    workdir: /srv/workspaces/customer-support
```

The cockpit exposes these choices under **Harnesses and native tools**, and
the Run page selects only a manifest-granted harness name. CLI overrides may
assert the exact command/arguments but cannot widen the ratified access.
Profile isolation prevents accidental global configuration inheritance; it is
not a filesystem or network sandbox. A full inherited profile is therefore a
legitimate, visibly broad grant rather than a misleadingly “safe” preset.
For Goose, Apiary also pins `GOOSE_MODE` to `chat`, `approve`, or `auto` from
the ratified access level. Other harnesses must faithfully emit ACP permission
requests for title-level curation to be enforceable; the signed log records
what Apiary approved and what the harness reported, not an imaginary sandbox.

## Layout

```
crates/apiary-core      manifest, identity, custody, keystore, log, ceremony — the substrate
crates/apiary-runtime   inference providers, routing, spend authority, run loop
crates/apiary-cli       `apiary` — the host's JSON front door
crates/apiary-hostd     lib + daemon: REST + AG-UI SSE + NIP-98 auth + cockpit at /
crates/apiary-desktop   Tauri app: embedded local host or SSH-connected remote cockpit
docs/SPEC.md            the design: architecture, governance, failure modes, phases
```

## License

Apache-2.0

## Companion: apiary-voice

[prellr/apiary-voice](https://github.com/prellr/apiary-voice) is the voice
companion for Apiary agents — a menu-bar Mac app: hold a key (or just talk;
Silero VAD decides turns), your words are transcribed on-device, sent to the
agent through the host's governed run endpoint, and the reply comes back
spoken (system voice or a local Kokoro server) with the text in a small HUD.
Routines that deliver to `companion` are spoken through it. Voice never
crosses the wire.
