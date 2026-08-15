# Apiary

A host for **portable agents** — durable principals with self-owned cryptographic
identity (nostr), not sessions welded to a platform.

An agent is four things, none of which is the model: **identity** (a nostr
keypair), **skillset** (manifest-declared connectors), **memory** (signed log +
semantic index), and **permissions** (human-owned floors + encrypted credential
grants). The model is rented, swappable cognition: *inference in, connections out*.

Read the full design: [docs/SPEC.md](docs/SPEC.md).

## Status

Phases 0–3 are complete and live-proven against production infrastructure
(public nostr relays, a production Buzz workspace, real MCP servers, live
model runs). What exists today:

**The substrate** (`apiary-core`)

- Manifest schema v1 — the agent's constitution: identity, inference pool,
  routing, connectors, memory, presence, governance, lease
- Identity: nostr keypair (BIP-340); custody with NIP-44 seal/open,
  per-agent isolation, JIT decrypt, zeroizing buffers
- Dev keystore: NIP-49 (ncryptsec) encrypted keys at rest, 0600/0700 modes
- Signed episodic log: chained nostr events with privacy tiers
  (public / self / local), tamper detection
- Founding ceremony: the agent signs its manifest hash, a human suspend-key
  holder countersigns — both land in the public log. **Unratified agents
  refuse to run**, and any amendment suspends until re-ratified.

**The runtime** (`apiary-runtime`)

- Inference pool: Anthropic (raw Messages API), Ollama, mock — slots, not
  identity; routing = floors clamp → rules → default, resolved host-side
- Spend authority: `tokens_per_day` as a hard ceiling via atomic
  reservations taken before every model call
- Governed run loop: budget → route → hydrate memory (semantic index +
  recency tail) → infer → tool loop → signed checkpoint entries
- Provenance framing: memory, tool results, and workspace messages are
  DATA in the working set; instructions come only from the constitution
  and the operator's task (proven live: a channel mention asking an agent
  to use its connectors gets a polite refusal)
- Connectors, default-deny: `nostr-publish` (relay-allowlisted), **`mcp`**
  (see below), each grant a ratified manifest amendment with credentials
  sealed to that agent alone
- MCP client: revision 2026-07-28 (stateless, per-request `_meta`,
  `server/discover` era probe) with automatic fallback to
  `initialize`-era servers; stdio (scrubbed-env subprocess) and
  Streamable HTTP (mirror headers, `x-mcp-header`, SSE); OAuth grants
  (RFC 9728 → RFC 8414 → PKCE → RFC 9207) with tokens sealed to the agent;
  `caps.allowed_tools` required — the server offers, the manifest decides
- Foreign harnesses via ACP (proven with claude-code-acp): permission
  requests decided host-side, default deny, harness attribution in the log
- Tiered log publication: public entries publish as-is, self-tier publish
  NIP-44-wrapped to the agent's own key, local never leaves; the remote
  copy is fetched, verified, and decrypted back — portable memory, proven
- Buzz membership: NIP-42 auth with the agent's own key — channels,
  posting, profiles, and a mention listener that answers through the
  governed run path (loop-guarded, causally timestamped)
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
  (the signer must be a suspend key of the agent it touches)

Remaining roadmap: NIP-46 remote-signer custody, OS sandbox for ACP
subprocesses, per-event relay connections → a pooled client.

## Quick start

The fastest path is the desktop app — everything below (and everything the
CLI can do) is operable from the GUI with inline explanations:

```bash
cargo run -p apiary-desktop
```

Or the CLI:

```bash
cargo build

export APIARY_PASSPHRASE=…   # dev keystore passphrase (NIP-49)

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

The desktop app runs the full `apiary-hostd` router in-process on a loopback
port and opens the cockpit in a native window. Tabs, each with inline
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
  each entry), including MCP servers and OAuth-granted remotes
- **Credentials** — NIP-44 seal/open against the agent's key
- **Header** — host status chips, keystore lock/unlock (passphrase lives in
  memory only), npub⇄hex key tool

Runtime governance is supervised, not scripted: activate an agent whose
manifest declares `presence.buzz` and the host starts its listener, restarts
it if it dies, bounces it the moment the manifest changes (returning only
once re-ratified), stops it on deactivation, and coordinates with other
hosts through the lease — contested starts refuse and name the holder;
taking over a live agent is always a human act.

Security posture: the embedded daemon binds `127.0.0.1` on an ephemeral port
and requires a per-launch random token that only the app's own webview
receives — other local processes can't drive it. The keystore starts locked
unless `APIARY_PASSPHRASE` is set. `ANTHROPIC_API_KEY` in the app's
environment enables anthropic-routed runs and model-drafted foundings.

The plain daemon (`apiary-hostd`) serves the same cockpit at `--bind` for
headless hosts; add `--auth nip98` beyond localhost.

## Layout

```
crates/apiary-core      manifest, identity, custody, keystore, log, ceremony — the substrate
crates/apiary-runtime   inference providers, routing, spend authority, run loop
crates/apiary-cli       `apiary` — the host's JSON front door
crates/apiary-hostd     lib + daemon: REST + AG-UI SSE + NIP-98 auth + cockpit at /
crates/apiary-desktop   Tauri app: the hostd router in-process, cockpit in a native window
docs/SPEC.md            the design: architecture, governance, failure modes, phases
```

## License

Apache-2.0
