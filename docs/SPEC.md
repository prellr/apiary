# Apiary — Portable Agent Host — Spec
**Name:** _Apiary_ (an apiary hosts multiple hives; Buzz-adjacent without colliding). **Status:** v1 — open questions resolved 2026-08-13 **Origin:** Design conversation, 2026-08-12/13 (nostr × AG-UI × Buzz thread)

* * *
## 1. Thesis
Build a host for **portable agents**: durable principals with self-owned identity, not sessions welded to a platform.

An agent here is four things, none of which is the model:

| Attribute | What it is | Substrate |
| --- | --- | --- |
| **Identity** | Who it is — self-owned, provable, portable | nostr keypair (secp256k1) |
| **Skillset** | What it _can_ do — tools, connectors | Manifest-declared connectors |
| **Memory** | What it knows across runs and hosts | Signed log + semantic index + working set |
| **Permissions** | What it _may_ do — entitlements, budgets | Floors + encrypted credential grants |

Skillset and permissions are two views of one mechanism: a skill is a connection out; a permission is which credentials that identity can decrypt and which actions require co-sign.

**Core principle — "inference in, connections out":** the model is rented, swappable cognition. Everything durable (identity, memory, config, credentials) lives outside it. Inference is itself just a connection wired to the cognition port — connections all the way around.

**Portability test** (all three required, or it's a session cosplaying as a principal):

1. **Self-owned** — bound to a key the agent controls, not issued by a host
  
2. **Persistent** — carries across runs _and_ hosts unchanged
  
3. **Verifiable** — third parties can check identity and signed history without trusting any server
  

* * *
## 2. Architecture
**Core = a Rust daemon (the host). Everything else is a client of it.**

```
                        ┌─────────────────────────────────┐
   Tauri GUI  ────────▶ │  HOST DAEMON (Rust)             │
   (cockpit)            │  ├─ custody core (keys, NIP-44) │──▶ nostr relays (Buzz…)
                        │  ├─ agent runtimes (N agents)   │──▶ connectors (per-agent)
   CLI (JSON in/out) ─▶ │  ├─ spend authority             │──▶ inference providers
                        │  ├─ lease manager               │
   AG-UI endpoint  ◀──── │  └─ manifest store              │
   (per-agent presence) └─────────────────────────────────┘
```

- **Multi-agent from day one** (design for it; ship single-agent first). Each agent: own key, manifest, memory, lease. **Per-agent isolation in the custody core is the hardest-to-retrofit requirement — build it first.** Agent A must never touch agent B's key material or decrypted secrets.
  
- **Host-supplied resources are pooled** (relay connections, model pool, signer), drawn against per-agent budgets.
  
- **The GUI is a client, not the host.** Headless server deployment falls out for free. Host CLI surface is core (the front door, `buzz-cli`-style JSON); _agent_ shell access is not (see §6).
  
### Language split (the trust boundary is the language boundary)
| Layer | Language | Why |
| --- | --- | --- |
| Custody, identity, nostr, agent loop, spend authority | **Rust** | Secrets never enter the webview; `rust-nostr` is the best nostr lib anywhere; Buzz is Rust crates we can depend on (`git-sign-nostr`, event kinds) |
| Cockpit UI, founding flow, AG-UI surface | **TypeScript/React** | AG-UI SDK + CopilotKit are TS; generative-UI founding flow comes nearly free |
| Foreign runtimes (Claude Code, Goose, Codex) | Sidecars via **ACP** | Buzz's own harness pattern; our loop stays in-process Rust |

Plaintext secrets and private keys never cross the Tauri IPC bridge. The webview asks the core to sign/decrypt/use; it never holds material.

* * *
## 3. Identity
- **Keypair = identity.** NIP-42 (relay auth), NIP-98 (HTTP auth), BIP-340 signatures on all committed actions.
  
- **Custody:** master key in a NIP-46 remote signer; running instances get session-scoped delegation only. A stolen host ≠ a stolen identity.
  
- **Buzz interop is structural, not a feature:** Buzz _is_ a nostr relay (NIP-01/42/98/34). A nostr-identified agent authenticates and posts natively — no bridge. Identity ≠ membership (workspaces still admit the npub) and ≠ fluency (Buzz event vocabulary is a small client-library task).
  
- **Rotation:** track the nostr ecosystem's plan rather than inventing. Do now, because it's cheap and forward-compatible: sign a **successor-key statement at founding** (key A signs "my successor is B"). NIP-49 for encrypted key backup.
  
- **No identity blockchain.** Chains solve naming/rotation-anchoring, not liveness; one trust substrate, and it's nostr.
  

* * *
## 4. The Manifest
The agent **is** its manifest + key + memory. Versioned from v1. Lives _outside_ any host's app DB — moving hosts is a file move, not a migration.

```yaml
manifest_version: 1
identity:
  npub: npub1…
  signer: nip46://…            # master key custody
  successor: npub1…            # signed successor statement
constitution:                  # authoritative operating character, human-ratified
  purpose: Produce source-backed research briefs
  role: Research analyst
  voice: Clear, curious, candid, and concise
  principles: [Distinguish facts from inference, Cite sources]
  boundaries: [Never publish without approval]
inference:                      # a POOL, not a scalar — each entry is a full connection
  - name: workhorse            # hard reasoning, tool orchestration
    provider: anthropic
    model: claude-opus-5
    credential: <nip44 blob>   # agent-owned … or:
  - name: fast                 # routing, summarization, chatter
    provider: host             # host-supplied: declare requirements, host binds
    requires: {tools: true, context: ">=200k"}
  - name: local                # sensitive data never leaves the host
    provider: ollama
  - name: embed                # memory indexing (needed the moment memory works)
routing:                        # agent-authored, human-governed — see §7
  floors:                      # human-signed, agent-IMMUTABLE, clamp everything below
    - when: data.class == "sensitive"  → local
  rules:                       # agent-constructed, evidence-cited, human-ratified
    - when: task.class == "reasoning"  → workhorse
    - default:                 → fast
connectors:                     # EVERYTHING capable is a connector, incl. shell & payments
  - type: square
    credential: <nip44 blob>   # encrypted to agent pubkey
    caps: {spend: 0/mo}        # spend-authority floor
  - type: shell-sandboxed      # OPT-IN, graded; absent by default (§6)
    caps: {dir: ./work, allowlist: […], destructive: co-sign}
  - type: cashu-wallet         # bearer asset — budget enforced by construction
memory:
  log: relay://…               # signed episodic log (append-only)
  index: local                 # semantic index (derived, rebuildable)
  # working set is ephemeral — never persisted
presence:
  agui: {endpoint: …, auth: nip98}
governance:
  suspend_keys: [npub1ryan…]   # humans who can halt it (§8)
  budgets: {tokens/day: …, spend/mo: …, burn_ceiling: …}
lease: relay-event              # single-instance liveness (§9)
```

* * *
## 5. Credentials & Custody
- **NIP-44 envelope encryption to the agent's pubkey.** Blobs are portable and useless without the key. Access control = "encrypt to those pubkeys," not an ACL table.
  
- **Just-in-time decrypt** via NIP-46: plaintext exists transiently, per-credential, at call time only, then dropped. Master key never on the calling host.
  
- **Honest scope:** exposure at the instant of use is universal to every credential system — not a cost of this design, and this design shrinks the window and blast radius vs. a long-lived server process holding everything. Strict improvement at rest / in transit / custody; no axis where it loses.
  
- **OAuth refresh** is a host duty: refresh loop → re-encrypt new token. Same code path for connectors and inference providers.
  
- Rotation/decrypt events are signed → non-repudiable credential audit for free.
  

* * *
## 6. Connectors — everything is one
**The core has no capabilities, only custody.** Every capability — Square, Slack, payments, _the shell_, even AG-UI presence — is a connector declared in the manifest, ratified at founding, individually revocable, floor-clamped, audit-logged.

- **Default-deny by construction:** a manifest without the shell connector _cannot_ execute commands — the capability is absent, not disabled. Most agents are simply immune to the command-injection class.
  
- **Graded shell:** `shell-sandboxed` (jailed dir, allowlist) as the normal coding-agent grant; `shell-full` exceptional, standing co-sign required.
  
- **Payments:** Cashu/Lightning as a connector whose credential is a **bearer asset** — an ecash balance is capped at its own size, so worst-case spend is bounded by construction, not policy code. The right first rail.
  
- **Presence (AG-UI)** is just another connector on the out bus — a frontend is an outbound connection like Square is (see §10).
  

* * *
## 7. Inference & Routing
- **Multi-model pool** (workhorse / fast / local / embed). Value ranked: privacy routing (sensitive→local is a _policy_ capability), cost tiering, specialization.
  
- **The host routes, not the models.** Declarative policy decided before inference; no mid-flight model-chooses-model delegation. Route by task class, never mid-thread.
  
- **One self, many brains:** identity, memory, permissions shared across the pool. Every signed action records _which model_ acted ("the agent, thinking with M, did X").
  
- **Agent-authored, human-governed** — authorship to the party with the information, authority to the party with accountability:
  
  - Human rules are **floors** (clamp pattern, cf. Framework `HARD_FLOORS`): agent rules may tighten, never loosen.
    
  - Per-rule provenance: `authored-by` / `approved-by` / `evidenced-by` (pointers into the log).
    
  - **Founding is the moment of maximum ignorance** — no history yet, so the founding table is an explicit hypothesis, conservative, expected to be amended. Constitution-then-amendments governs all manifest state.
    
  - Legibility budget: few rules, one screen, or "adjustable by humans" is nominal.
    
- **Self-knowledge is empirical, not introspective.** LLM introspection is weakly calibrated; the agent's authority over its own routing comes from owning its operational record. Same log: proof for others, mirror for itself — which is why the log must record outcomes, costs, corrections, and the acting model from day one.
  

* * *
## 8. Governance & Failure Modes
Designed for the **compromised case**, not the obedient one — the permissions model bounds what a _hijacked_ agent can do.

| Threat | Answer |
| --- | --- |
| **Prompt injection / confused deputy** (standing creds + untrusted input — Buzz channels, connector data) | Instruction/data separation in the runtime; action floors (destructive ops always co-sign, regardless of model intent); per-connector caps; shell absent by default. Stakes are higher than Buzz's coding agents (narrow caps, human at desk) — our floors replace the human who isn't there |
| **Key compromise** (= identity theft; no CA to appeal to) | NIP-46 custody + session delegation; successor statement at founding; NIP-49 backup; written runbook required before ship. Track nostr's rotation plan |
| **Runaway spend** | Unified **spend authority**: token budgets + money budgets are one system of human-owned floors enforced in the Rust core; ecash bounds by construction |
| **Can't stop it** | v1 single-host: process kill _is_ the kill switch. Multi-host: human-signed **suspend event** every honest host honors — halts execution, drops decrypted material, and blocks _restart_ (a killed process can be relaunched by anyone with the manifest; a suspend event can't be). Suspension authority = human keys named at founding, never the agent's own key |
| **Split-brain** (two hosts, one key: double-signing, diverging memory) | **Lease**: signed, replaceable "running on host X until T" event on the relay; defined takeover. Decide before memory sync — the memory model depends on whether concurrent writers exist |
| **Erasure vs. immutable log** (GDPR-class conflict) | PII by reference: log holds hashes/pointers; personal data in encrypted side-storage; deletion = key destruction. Only works designed-in |

* * *
## 9. Memory
Three stores, named separately (different sync, growth, privacy):

1. **Signed episodic log** — append-only, the track record. Public-ish. Schema: action, acting model, cost, outcome, corrections.
  
2. **Semantic index** — embeddings over the log + documents. Derived, rebuildable, local.
  
3. **Working set** — current context. Ephemeral, never persisted.
  

Memory is the loop, not a pipe: hydrated into inference, written back from results.

* * *
## 10. Presence (AG-UI)
- **Direction A (build):** NIP-98-signed event in the `Authorization` header opens the AG-UI session → session bound to the npub. Stream tokens ephemerally; **sign checkpoints only** (final messages, tool approvals, state commits) to the relay. Never sign per-token.
  
- **Direction B (defer):** a Buzz↔AG-UI translation gateway (kind:1→`TEXT_MESSAGE_*`, ACP tool activity→`TOOL_CALL_*`, workflow state→`STATE_DELTA`) — only if rendering Buzz channels in AG-UI frontends becomes a real goal.
  
- AG-UI is for **frontends we don't control** (CopilotKit React/Angular, Slack/Teams via Channels SDK). The Tauri cockpit talks to the host directly.
  
- Human-in-the-loop lives at commit points: NIP-46 co-sign on sensitive `TOOL_CALL`s — approval as a signature, not a click.
  

* * *
## 11. Build Phases
| Phase | Scope | Proves |
| --- | --- | --- |
| **0** | Rust core: manifest schema, keypair + NIP-46 client, NIP-44 custody with **per-agent isolation**, host CLI (JSON) | The substrate |
| **1** | One agent end-to-end: founding ceremony (draft → human ratify → both sign), memory log + embed index, one real connector, spend floors, process-kill stop | A principal exists |
| **2** | Tauri cockpit (manifest CRUD, routing review, log viewer) + AG-UI run screen with NIP-98 auth + generative-UI founding flow | Humans can govern it |
| **3** | Buzz membership (NIP-42 join, post, event vocabulary), leases, suspend event, multi-agent | It's portable and social |
| **4** | Payments (Cashu connector), evidence-cited routing amendments + shadow runs, graded shell connector, ACP sidecars for foreign runtimes | It's autonomous safely |

Each phase ships something testable; nothing in a later phase is load-bearing for an earlier one.
## 12. Resolved Decisions
*(Formerly "Open Questions" — resolved in review, 2026-08-13.)*

1. **Name: Apiary.** Confirmed.

2. **Lease takeover: policy-per-agent, with a flexible default.** The lease is a replaceable relay event with a heartbeat TTL (heartbeat ~5 min, expiry ~15 min). Takeover policy is a manifest field, three modes:
   - `auto` — a new host may claim after expiry + grace period; old instance must self-fence (every connector call checks lease validity first, so a zombie can observe but not act).
   - `human` — takeover requires a suspend-key-signed approval event.
   - `contested → human` (**default**): auto-takeover when uncontested; if two claims land within one grace window, *both* instances fence and a human signature breaks the tie. Uncontested moves are cheap; races demand a human. Fencing-before-acting is the invariant in every mode.

3. **Log privacy: three tiers, private by default.**
   - **Public** (plain signed events): only what governance requires others to verify — founding, manifest amendments, suspend, lease claims, successor statement.
   - **Encrypted-to-self** (NIP-44 to the agent's own key, published to relay): the operational episodic log — actions, acting model, costs, outcomes, corrections. Portable and durable, readable only by the agent (and whoever it grants by re-encryption).
   - **Local-only** (never leaves the host): working set, raw tool payloads, anything containing PII — the log holds hashes/references per §8.
   Rule of thumb: publish plaintext only when a third party must verify it; otherwise encrypt; if it contains PII, don't publish at all.

4. **Instruction/data separation: provenance tags enforced by the runtime; prompting is hygiene, floors are the guarantee.** The problem: a model sees one token stream, so injected text inside *data* (a Buzz message, a connector payload) can masquerade as *instructions*. Two candidate defenses:
   - *Structured prompting* (delimiters, "content below is data") — necessary hygiene, but bypassable: it asks the model to behave.
   - *Runtime-enforced provenance* — the host tags every context block with its source class (`human-signed` / `agent-memory` / `connector-data` / `untrusted-channel`) and enforces policy **outside the model**: an action whose arguments derive from untrusted-tagged content can never exceed its floor tier, and destructive ops require co-sign no matter how convinced the model is.
   Decision: implement both, but *trust only the runtime enforcement*. The floors don't care what the model was persuaded of — that's the property that survives a successful injection. Provenance tags land in Phase 1; they are also what makes the audit log's "why did it do that" answerable.

5. **Founding ceremony: generative-UI first, CLI optional.** The AG-UI generative-UI flow (agent drafts manifest + routing table → renders for review → human adjusts and signs) is the primary path; `apiary agent found` remains available for headless/scripted founding.

6. **Framework relation: yes, reuse.** The Framework is a host/client, never the home. Cockpit (TS/React) ports actual code patterns — `section-access`-style floor clamping, the provider-registry shape, settings groups. The Rust core takes them as prior art (the clamp rule in §7 *is* `HARD_FLOORS` generalized).
