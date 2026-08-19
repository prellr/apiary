# Apiary

**AI agents that remember, use tools, and remain under your control.**

Apiary is a desktop and server app for building AI agents that can work across
your services without being locked to one AI provider. Each agent keeps its own
identity, instructions, memory, and permissions, so you can change models, move
it between computers, or connect powerful external runtimes without starting
over or silently expanding what it can do.

[![CI](https://github.com/prellr/apiary/actions/workflows/ci.yml/badge.svg)](https://github.com/prellr/apiary/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

> Apiary is under active development. The desktop app, headless host, governed
> runtime, remote mode, connectors, skills, presence, and agent portability are
> implemented. Interfaces and manifest fields may still change.

## The idea

An Apiary agent has five durable parts:

| Part | What it controls |
| --- | --- |
| Identity | A self-owned Nostr keypair |
| Constitution | Purpose, role, voice, principles, and boundaries |
| Memory | A signed history plus local semantic retrieval |
| Capabilities | Explicit connectors, skills, inference, and harness access |
| Governance | The people or agents allowed to operate or change it |

The model is replaceable cognition. It is not the agent's identity and it does
not decide its own permissions.

```mermaid
flowchart LR
    U["People or manager agents"] --> H["Apiary host"]
    D["Desktop or remote client"] --> H
    H --> G["One governance gate"]
    G --> R["Agent runtime"]
    R --> I["Inference providers"]
    R --> C["Governed connectors"]
    R --> P["Presence channels"]
    R --> A["Optional ACP harnesses"]
```

Signed manifests and ratification events are the portable authority. The host
derives one small operational decision from them; task history, health, spend,
indexes, and UI state remain ordinary off-chain projections.

## What works today

- **Desktop and headless operation** — run Apiary locally, on a server, or use
  the desktop app through an SSH tunnel.
- **Replaceable inference** — Anthropic, OpenAI-compatible providers, xAI,
  Ollama, local endpoints, and mock inference with per-agent routing.
- **Governed tools** — built-in web, files, Git, Markdown vaults, Nostr, and
  MCP connectors. Write access is explicit and optional.
- **Portable skills** — standard `SKILL.md` instructions become ratified agent
  capabilities; missing connector requirements fail closed.
- **Durable memory** — signed, chained event history with public, self, and
  local privacy tiers plus semantic retrieval.
- **Multi-channel presence** — Buzz, Telegram, Slack, and external channel
  plugins share the same runtime and policy checks.
- **Per-agent harness policy** — ACP harnesses such as Claude Code, Goose, or
  Berd may be isolated, curated, fully enabled, sandboxed, metered, or denied
  for each agent independently.
- **Scoped management** — multiple Nostr identities can manage the host or
  individual agents as viewers, operators, editors, or governors.
- **Portable agents** — export, transfer, import, and relay-based recovery
  verify identity, signatures, history, and ratification before activation.
- **Management over MCP** — an outside agent can inspect and manage permitted
  Apiary environments without bypassing the normal authorization gate.

## Quick start

### Desktop

Requirements: a current Rust toolchain and the platform dependencies required
by [Tauri 2](https://v2.tauri.app/start/prerequisites/).

```bash
git clone https://github.com/prellr/apiary.git
cd apiary
cargo run -p apiary-desktop
```

On macOS, build the persistent signed executable with:

```bash
scripts/build-desktop.sh
```

This produces `target/release/Apiary` with a stable signing identifier so
macOS Keychain does not treat every rebuild as a different application.

### CLI

```bash
cargo build

# Development-only keystore passphrase. The desktop uses macOS Keychain.
export APIARY_PASSPHRASE='choose-a-passphrase'

# Create and ratify an agent.
target/debug/apiary agent new --name scout --suspend-key npub1…
target/debug/apiary agent ratify <agent-npub> --as <manager-npub>

# Run a governed task and verify its signed history.
target/debug/apiary run <agent-npub> --task "Summarize your purpose"
target/debug/apiary log verify <agent-npub>
```

State lives in `~/.apiary` unless `APIARY_HOME` is set. Never commit that
directory.

## Local and remote backends

The desktop normally embeds a loopback-only Apiary host. To keep agents and
credentials on a server, start the daemon there:

```bash
apiary-hostd --bind 127.0.0.1:7777 --auth open
```

In the desktop app, open **Host status**, add the SSH server, and select
**Switch**. Apiary creates a noninteractive loopback tunnel; inference,
credentials, files, channels, and agent state remain on the server.

Keep an `open` daemon bound to server loopback. Use `--auth nip98` whenever a
host is reachable beyond a trusted SSH boundary.

## Governance in practice

- New agents do not run until a manager ratifies their manifest.
- Constitutional or capability changes suspend the agent until ratified again.
- Host managers control installation-wide operations; agent managers are
  scoped to named agents.
- An agent can be a manager of another agent, but cannot govern itself.
- Connectors and harnesses are default-deny. A model request cannot expand a
  ratified grant.
- Credentials are encrypted to the receiving agent and opened only when used.
- Memory, tool results, files, and channel messages are treated as data, not
  trusted instructions.
- Daily model budgets reserve tokens before inference. Harnesses with unknown
  usage must be explicitly estimated or intentionally marked unmetered.

## Connectors, skills, and harnesses

These are deliberately separate:

| Mechanism | Purpose | Authority |
| --- | --- | --- |
| Connector | Gives an agent access to a service or local resource | Named, ratified grant with read/write limits |
| Skill | Teaches a repeatable workflow | Ratified `SKILL.md`; grants no tools itself |
| Harness | Supplies a complete external agent runtime | Per-agent access, profile, sandbox, and metering policy |

Harness policy can expose only inference, a curated tool set, or the harness's
full native surface. Its profile can be isolated from global credentials and
extensions or intentionally inherited. File and network sandboxing are
separate controls and fail closed when a requested sandbox is unavailable.

## Apiary control MCP

Every host exposes a stateless MCP endpoint at `POST /mcp`. It supports:

- `apiary_describe`
- `apiary_list_agents`
- `apiary_get_agent_environment`
- `apiary_request`

Human callers authenticate with NIP-98. A hosted manager agent can create a
time-limited `apiary_…` bearer token from its agent page. Tokens identify the
caller but grant no additional authority: each operation re-enters the same
host and per-agent authorization checks used by the desktop and REST API.

Credential plaintext, host unlock, key export, and other sensitive local
operations are intentionally unavailable through control MCP.

## Security model

Apiary is designed around narrow authority and explicit transitions:

- Nostr/BIP-340 agent identity with encrypted key custody
- signed manifests, ratification, and tamper-evident logs
- per-agent encrypted credentials and default-deny capability grants
- DNS and redirect checks for public web access
- jailed roots for file, Git, and vault connectors
- scrubbed environments for connector and harness subprocesses
- authenticated remote control with a local management audit chain
- single-host presence leases with human-controlled takeover

See [docs/SPEC.md](docs/SPEC.md) for architecture, failure modes, schemas, and
protocol details. Apiary is security-sensitive software and has not yet had an
independent security audit.

## Repository layout

```text
crates/apiary-core      identity, manifests, custody, logs, and ratification
crates/apiary-runtime   inference, routing, budgets, memory, tools, and runs
crates/apiary-cli       command-line interface
crates/apiary-hostd     daemon, REST/AG-UI, MCP control, auth, and web cockpit
crates/apiary-desktop   Tauri desktop app and remote-backend switcher
docs                    design and plugin specifications
```

Useful references:

- [System specification](docs/SPEC.md)
- [Channel plugin protocol](docs/CHANNEL_PLUGINS.md)
- [Presence plugin scope](docs/SCOPE_presence-plugins.md)
- [Routines scope](docs/SCOPE_routines.md)
- [Sealed handoffs scope](docs/SCOPE_sealed-handoffs.md)
- [Voice and modalities scope](docs/SCOPE_voice-and-modalities.md)

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Please keep security boundaries visible in code and documentation. New tools
should enter through a governed connector or harness grant rather than an
implicit environment capability.

## Roadmap

- NIP-46 remote-signer custody
- OS sandbox coverage for additional ACP environments
- relay delivery for sealed handoffs
- signed-log checkpointing and compaction
- independent security review

## Companion: apiary-voice

[apiary-voice](https://github.com/prellr/apiary-voice) is an optional macOS
voice companion. It performs local transcription and speech, while tasks still
enter through Apiary's governed run endpoint.

## License

Apache-2.0
