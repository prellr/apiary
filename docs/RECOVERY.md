# Backup and recovery runbook

This runbook describes the current NIP-49 host. It does not claim to solve a
compromised agent key. NIP-46 remote-signer custody, successor-key activation,
and ecosystem-compatible key rotation remain release work.

## What must be backed up

Apiary state lives in `APIARY_HOME`, or `~/.apiary` when that variable is not
set. A host backup must preserve the complete directory and file permissions,
including encrypted identities, manifests, ratifications, signed logs,
manager assignments, connector definitions, control-token revocations, and
host configuration.

Agent export is a portability mechanism, not a complete host backup. Keep both:

- encrypted offline snapshots of the entire state directory; and
- current sealed exports for individually portable agents.

Never store the workspace passphrase, Nostr private keys, OAuth refresh tokens,
or unsealed exports in the same location as the backup archive.

## Consistent backup procedure

1. Record the Apiary version, host ID, state path, and active agent leases.
2. Stop new tasks and presence listeners.
3. Lock and stop the host so no manifest, log, token, or index file can change
   during the copy.
4. Copy the complete state directory to encrypted offline storage while
   preserving permissions and timestamps.
5. Generate and record a cryptographic checksum for the encrypted archive.
6. Restart the host and verify every previously active presence channel
   returns healthy.

The exact service stop/start commands are deployment-specific and must be
recorded beside each host's operational configuration.

## Restore drill

Perform this drill on an isolated replacement host before every public release:

1. Install the candidate Apiary release without copying application binaries
   from the failed host.
2. Keep the replacement disconnected from public presence channels.
3. Restore the complete state directory with its original permissions.
4. Start Apiary in a private boundary and unlock it with the separately stored
   passphrase.
5. Verify each agent's npub, ratified manifest, manager roles, connector grants,
   inference routes, and signed log chain.
6. Run read-only smoke tasks. Confirm imported or recovered agents remain
   inactive until a manager deliberately activates them.
7. Transfer or take over each presence lease intentionally; verify the old host
   can no longer publish as the active presence.
8. Revoke obsolete browser sessions and control tokens, rotate external
   service credentials where exposure is possible, then enable public traffic.
9. Record elapsed recovery time, missing data, manual interventions, and the
   exact release commit used.

## Key compromise

If an agent private key may have been exposed, restoring the same NIP-49 blob
does not repair the compromise. Suspend the agent and its external credentials,
preserve audit evidence, revoke control tokens, and do not reactivate it as a
trusted identity. Public release requires a separately tested successor-key and
NIP-46 recovery procedure for this case.
