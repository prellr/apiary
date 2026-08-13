# Apiary

A host for **portable agents** — durable principals with self-owned cryptographic
identity (nostr), not sessions welded to a platform.

An agent is four things, none of which is the model: **identity** (a nostr
keypair), **skillset** (manifest-declared connectors), **memory** (signed log +
semantic index), and **permissions** (human-owned floors + encrypted credential
grants). The model is rented, swappable cognition: *inference in, connections out*.

Read the full design: [docs/SPEC.md](docs/SPEC.md).

## Status — Phase 0 (substrate)

- [x] Manifest schema v1 (serde + substrate invariants)
- [x] Identity: keypair generation, npub parsing (nostr / BIP-340)
- [x] Custody: NIP-44 seal/open with **per-agent isolation**, JIT decrypt, zeroizing buffers
- [x] Dev keystore: NIP-49 (ncryptsec) encrypted keys at rest, 0600
- [x] Host CLI (`apiary`): JSON in/out — agent founding, manifest validation, credential seal/open
- [ ] NIP-46 remote-signer custody (replaces dev keystore as key source)
- [ ] Episodic log (signed events) — Phase 1
- [ ] Founding ceremony with human ratification — Phase 1

## Quick start

```bash
cargo build

export APIARY_PASSPHRASE=…   # dev keystore passphrase (NIP-49)

# Found an agent (requires a human suspend key — suspension authority
# never rests with the agent's own key)
apiary agent new --name scout --suspend-key npub1…

apiary agent list
apiary manifest validate ~/.apiary/agents/<npub>/manifest.yaml

# Seal a connector credential to the agent's key (NIP-44)
echo -n "$SECRET" | apiary credential seal <npub>
```

State lives in `~/.apiary` (`APIARY_HOME` to override). Never commit it.

## Layout

```
crates/apiary-core   manifest, identity, custody, keystore — the substrate
crates/apiary-cli    `apiary` — the host's JSON front door
docs/SPEC.md         the design: architecture, governance, failure modes, phases
```

## License

Apache-2.0
