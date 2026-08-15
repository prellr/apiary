# Scope: Sealed handoffs — key-addressed agent export
**Goal.** Export an agent addressed to a recipient's npub: no shared secret in flight, sender authenticity, and whole-bundle confidentiality (local-tier memory included). The passphrase handoff stays as the zero-setup option.
## The envelope
A sealed handoff is one nostr event:

| Field | Value |
|---|---|
| `kind` | **4602** (`apiary-handoff`) |
| `pubkey` (author) | **the agent's own key** — the agent signs its own handoff |
| `tags` | `["p", <recipient hex>]` |
| `content` | NIP-44 ciphertext (agent secret key → recipient public key) of the **bundle JSON v1** |

Written to a file (`*.apiary-sealed.json`) for now; because it is a standard signed event, relay delivery ("send an agent to an npub like a DM") becomes a natural follow-up with no format change.

**Inner key handling.** The bundle's traveling `key.ncryptsec` must be openable by the recipient, but they don't know the sender's keystore passphrase. Inside the sealed envelope, confidentiality is already guaranteed, so the bundle carries one new optional field:

- `key_passphrase`: a one-time random secret (CSPRNG, never shown to a human). Export re-encrypts the traveling key under it; import uses it automatically as the bundle passphrase, then — as today — re-encrypts under the recipient's own keystore passphrase on arrival.
  

The plain (unsealed) bundle format is unchanged; `key_passphrase` never appears outside ciphertext.
## Verification on import
Sealed imports add an envelope layer in front of the existing pipeline:

1. Envelope: event parses, signature verifies, kind is 4602.
  
2. **Self-consistency:** envelope author == the npub inside the decrypted bundle. The agent being handed over is the agent that signed the handoff.
  
3. Recipient match: the keystore key used to decrypt == the `p` tag.
  
4. Then the existing pipeline, unchanged: key↔npub↔manifest agreement, every log signature, chain, ratification, index rows verified against the log.
  

What this closes that the passphrase path cannot: **truncation and omission**. Today an interceptor can drop the log tail (still a valid shorter chain) or strip the index invisibly; any such edit now breaks the envelope signature. It also closes the **plaintext local-tier gap**: a passphrase bundle's log is readable by anyone holding the file — a sealed bundle is opaque to everyone but the recipient.

## Export modes — protection is optional, never required
Three modes, choosing **zero or one** of the two flags:

1. **Plain** (no flag): the traveling key stays under the keystore
   passphrase — for moving agents between your own hosts. Neither an npub
   nor a passphrase is required; this mode remains first-class.
2. **`--export-passphrase <secret>`**: handoff-locked, zero recipient setup.
3. **`--to <npub>`**: sealed envelope, no secret in flight.

Import auto-detects all three. The test plan asserts each mode round-trips.
## Surface changes
**CLI**

- `agent export --to <npub>` — mutually exclusive with `--export-passphrase`; needs the keystore passphrase (unlock the agent key to sign + ECDH).
  
- `agent import <file> [--as <recipient-npub>]` — auto-detects sealed vs plain. `--as` picks the keystore-held recipient key; default: the local key matching the envelope's `p` tag, with a clear error naming candidates when absent.
  
- `agent recover` unchanged.
  

**API / GUI**

- Export body gains `to_npub`; Portability section gets a "seal to npub" input beside the handoff-passphrase field (exactly one of the two).
  
- Import accepts envelope JSON in the same paste box; help text explains a sealed bundle needs the recipient's key present in this keystore and the keystore unlocked.
  
## Prerequisite the recipient must meet
Their receiving key must live in their Apiary keystore (the same way your `ryan` governor key does). That's the trade against the passphrase path, stated plainly: key-sealing needs the recipient's npub up front and their key on the destination host; the passphrase needs neither. Both stay.
## Security notes
- Static ECDH, no forward secrecy — acceptable for a one-shot artifact whose payload is itself re-encrypted at rest on arrival; noted, not mitigated.
  
- The one-time `key_passphrase` exists only inside ciphertext and in memory during import.
  
- Governance is unchanged by transport: the key lets the recipient act AS the agent; amending the constitution still requires a listed suspend key. Full ownership transfer remains: amend `suspend_keys` → ratify → export.
  
## Tests & live proof
- Unit: seal→open round trip; author/bundle-npub mismatch refused; wrong recipient key refused; ciphertext tamper refused; index-stripping refused (envelope signature breaks); **plain export with neither flag still round-trips** (both protections optional, none required).
  
- Live: seal bee to the `test-human` key → import into a fresh home that holds only that recipient key → arrives ratified, full memory, key re-encrypted under the new home's passphrase; all refusal paths exercised.
  
## Out of scope (named follow-ups)
1. **Relay delivery** of kind-4602 handoffs (subscribe/claim flow).
  
2. Governor countersignature (`--sign-as`) for "sent by Ryan" attestation — the ratification chain already proves governance, so this is optional provenance, not security.
  
3. Whole-bundle symmetric encryption for the _passphrase_ path (closing its plaintext local-tier gap too).
  
## Estimate
Core envelope seal/open + import auto-detect ≈ 160 lines; CLI/API/GUI ≈ 150; tests + live proof ≈ 100. A half-day chunk, no new dependencies.

---
comments:
  c1:
    body: Integrated — added an "Export modes" section making the three-mode contract explicit (plain / passphrase / sealed, zero-or-one flag), and the test plan now asserts the plain no-flag mode round-trips. Nothing is required; both protections are optional.
    by: AI
    at: "2026-08-15T21:22:00.000Z"
    re: s1
