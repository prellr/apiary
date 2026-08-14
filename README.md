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

## Layout

```
crates/apiary-core      manifest, identity, custody, keystore, log, ceremony — the substrate
crates/apiary-runtime   inference providers, routing, spend authority, run loop
crates/apiary-cli       `apiary` — the host's JSON front door
crates/apiary-hostd     daemon: REST + AG-UI SSE + NIP-98 auth + cockpit at /
docs/SPEC.md            the design: architecture, governance, failure modes, phases
```

## License

Apache-2.0
