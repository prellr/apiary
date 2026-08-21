# Apiary architecture boundaries

Apiary keeps signed authority small and moves ordinary work off-chain. The
signed manifest, ratification history, and manager assignments decide what is
allowed. Everything else—UI state, health probes, indexes, task execution, and
provider sessions—is a replaceable projection of that authority.

## One mutation path

Agent configuration changes go through `apiary-hostd::agent_store`:

1. Read the current manifest and retain its revision.
2. Authorize a typed operation against the current agent roles.
3. Build the complete replacement manifest in memory.
4. Lock the agent store and compare the expected revision again.
5. Write, sync, and atomically rename the replacement.

A stale editor receives `409 manifest_revision_conflict`; it cannot overwrite a
newer change from the cockpit, CLI, MCP manager, routine proposal, or another
host process.

## Fail-closed authorization

REST and management MCP requests enter the same host router. Agent routes are
classified as `View`, `Operate`, `EditDraft`, or `Govern`. A new mutating route
that has not been classified is `UnknownWrite` and requires governor authority.
This makes missing policy declarations restrictive instead of permissive.

Browser NIP-98 signatures open a short-lived, in-memory session. The session
avoids signing every request; it does not replace per-host or per-agent role
checks. State-changing browser calls also require the session CSRF value.

## Runtime hot path

The runtime records these stages independently:

- admission and governance projection
- budget reservation
- route selection
- transcription
- memory hydration
- connector binding
- provider binding/bootstrap
- engine and governed tool time
- first token
- signed checkpoint

`provider_bind_ms` separates credential/provider construction from model time,
so a future warm adapter is justified by measurements. Subscription CLI
profiles remain isolated per run until an adapter can stay warm without
allowing global instructions, tools, credentials, or state to cross agents.

Spend reservations use an RAII guard. Any error or early return releases the
reservation automatically; successful completion settles the measured usage.

## Cockpit modules

- `cockpit.js` renders navigation and workflows.
- `cockpit_api.js` owns authenticated fetches, NIP-98 session renewal, desktop
  session exchange, and sign-out.
- `cockpit_inference.js` owns declarative provider/model presentation metadata.

All cockpit modules are private, `no-store`, same-origin resources. The public
sign-in page does not load or disclose them.

## Invariants

- The model and external harnesses never grant themselves tools.
- Unknown write routes fail closed.
- A stale manifest writer cannot win.
- A dropped run cannot retain spending authority.
- OAuth callback errors do not print token responses or credentials.
- Generated AG-UI run IDs are unique when a client does not supply one.
- Locking clears admitted decrypted agent keys.
