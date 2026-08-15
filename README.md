# Apiary

A host for **portable agents** — durable principals with self-owned cryptographic
identity (nostr), not sessions welded to a platform.

An agent is four things, none of which is the model: **identity** (a nostr
keypair), **skillset** (manifest-declared connectors), **memory** (signed log +
semantic index), and **permissions** (human-owned floors + encrypted credential
grants). The model is rented, swappable cognition: *inference in, connections out*.

Read the full design: [docs/SPEC.md](docs/SPEC.md).

## Status

**Phase 0 (substrate)** — complete:

- [x] Manifest schema v1 (serde + substrate invariants)
- [x] Identity: keypair generation, npub parsing (nostr / BIP-340)
- [x] Custody: NIP-44 seal/open with **per-agent isolation**, JIT decrypt, zeroizing buffers
- [x] Dev keystore: NIP-49 (ncryptsec) encrypted keys at rest, 0600
- [x] Host CLI (`apiary`): JSON in/out — agent founding, manifest validation, credential seal/open

**Phase 1 (a principal exists)** — core loop landed:

- [x] Signed episodic log: chained nostr events (action / model / cost / outcome), privacy tiers, `log verify` tamper detection
- [x] Founding ceremony: agent signs manifest hash, human suspend-key ratifies — both in the log; **unratified agents refuse to run**
- [x] Inference: provider trait — Anthropic (raw Messages API, key or OAuth bearer), Ollama, mock; slot credentials JIT-decrypted through custody
- [x] Routing: floors clamp → rules → default, resolved by the host before inference
- [x] Spend authority: `governance.budgets.tokens_per_day` enforced in Rust before every call; refusals are logged
- [x] `apiary run`: one-shot loop — budget check → route → decrypt → hydrate memory from log tail → infer → signed log entry + spend record
- [x] Semantic index: `embed` inference slot (Ollama local, or deterministic hash fallback), incremental over the log, top-k retrieval merged into the working set alongside the recency tail
- [x] Provenance framing: memory and tool results labeled DATA in the working set; instructions come only from the constitution and the task (hard enforcement stays host-side in floors/caps)
- [x] Foreign harnesses via ACP: `run --harness acp --acp-cmd <bin>` — permission requests decided host-side (default deny), harness attribution in the log (proven live with claude-code-acp)
- [ ] NIP-46 remote-signer custody (replaces dev keystore as key source)
- [ ] OS sandbox for ACP subprocesses (harness-ungated reads currently follow the harness's own policy)
- [ ] Tauri cockpit + AG-UI run screen — Phase 2

## Quick start

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

Everything above — and everything the CLI can do — is also operable from the
cockpit GUI. The desktop app runs the full `apiary-hostd` router in-process
on a loopback port and opens the cockpit in a native window:

```bash
cargo run -p apiary-desktop
```

The window covers the whole surface, each section with inline explanations:

- **Overview** — identity, ratification state, governance (suspend keys,
  budget with a live spend meter), inference pool & routing, connectors,
  memory tiers & relays, lease, listener state
- **Run** — governed one-shot tasks with routing class / data class, streamed
  as AG-UI events; every model call lands as a signed log checkpoint
- **Log** — chain verification, publish to relays (tier-enforced: public
  plain, self NIP-44-wrapped, local never leaves), fetch-and-verify the
  remote copy
- **Manifest** — YAML editor with a field guide, save-amendment →
  auto-suspend → ratify cycle, and external ratification (export the
  unsigned event, sign with your own tooling, import)
- **Lease** — standing presence is single-host: the running host
  heartbeats an agent-signed lease event (kind 34601, replaceable) on the
  agent's log relays; a second host refuses to start while a live foreign
  lease exists and says whose it is. Takeover is `contested-human`: a
  button a person presses (Overview → Lease), never something hosts do on
  their own — the loser yields at its next heartbeat, bounding split-brain
  to one heartbeat interval. Graceful stops release the lease immediately.
- **MCP** — the `mcp` connector kind speaks the Model Context Protocol
  (revision 2026-07-28: stateless, per-request `_meta`, `server/discover`
  era probing) with automatic fallback to `initialize`-era servers — so
  both the current spec and today's npm ecosystem work. stdio servers run
  as scrubbed-environment subprocesses; Streamable HTTP servers get
  `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` mirror headers,
  `x-mcp-header` parameter mirroring, bearer tokens, or the full OAuth
  flow (RFC 9728 discovery → RFC 8414 metadata → PKCE → RFC 9207 iss
  validation → tokens sealed to the agent). `caps.allowed_tools` is a
  required allowlist: the server offers whatever it likes, the manifest
  decides what the agent may touch.
- **Connectors** — two layers: a host **connector library** of named
  configurations (kind + caps, no secrets, `connectors.yaml`), and
  per-agent **grants** that copy an entry into the agent's manifest with
  any credential NIP-44-sealed to that agent alone. Grants are
  constitutional (each one is a ratified amendment) and portable (they
  travel in the manifest; a destination host only needs to bind the kind).
  A live listener is bounced by the supervisor the moment its manifest
  changes and returns only once re-ratified.
- **Buzz** — profile, channel discovery/read/post/join, and the mention
  listener. Declare `presence.buzz: {relay}` in the manifest (constitutional
  — where the agent lives is ratified) and activate the agent: the host's
  supervisor starts the listener, restarts it if it dies, and stops it on
  deactivation. Manual start/stop remains as an override.
- **Credentials** — NIP-44 seal/open against the agent's key
- **Header** — host status, keystore lock/unlock (passphrase never touches
  disk), npub⇄hex key tool

Security posture: the embedded daemon binds `127.0.0.1` on an ephemeral port
and requires a per-launch random token that only the app's own webview
receives — other local processes can't drive it. The keystore starts locked
unless `APIARY_PASSPHRASE` is set; unlocking happens in the GUI and lives in
memory only. `ANTHROPIC_API_KEY` in the app's environment enables
anthropic-routed runs and model-drafted foundings.

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
