# Contributing to Apiary

Thanks for your interest. Apiary is early and moving fast; the spec is the
map — read [docs/SPEC.md](docs/SPEC.md) before proposing changes. PRs that
contradict the spec should argue with the spec first (amend it in the same
PR), not silently diverge from it.

## Ground rules

- **License:** Apache-2.0. By submitting a contribution you agree it is
  licensed under Apache-2.0 like the rest of the project (inbound = outbound).
- **Custody is sacred.** No code path may move private keys or decrypted
  secrets outside `apiary-core`'s custody module — the webview, CLI output,
  subprocess environments, and logs never see key material. PRs that widen
  the custody boundary will be declined regardless of the feature they enable.
- **Governance is host-side.** Floors, caps, and permission decisions are
  enforced in Rust, never delegated to model output. Prompt-level framing is
  hygiene, not enforcement.
- **Tests required.** `cargo test --workspace` must pass; new behavior needs
  a test that fails without it. Never commit real keys, state dirs, or
  relay-published content from your own agents.

## Building

```bash
cargo build
cargo test --workspace
cargo install --path crates/apiary-cli   # the `apiary` binary
```

The [README](README.md) has the quick start; `docs/SPEC.md` §11 has the
phase plan if you want to know where help is most useful.
