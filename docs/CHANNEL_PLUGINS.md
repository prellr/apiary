# The Channel Plugin Protocol — `apiary-channel/1`

Apiary agents hold *standing presence*: they live on platforms and answer
when spoken to. Built-in channels (buzz, telegram, slack) cover the common
cases; this protocol lets anyone add a platform without touching Apiary.

A channel plugin is **an executable**. The host spawns it with a scrubbed
environment (only `PATH`, `HOME`, `TMPDIR`, `LANG` survive) and speaks
newline-delimited JSON-RPC 2.0 over stdio — one message per line, stdout is
protocol-only, stderr is yours for logging.

The host keeps everything that matters: budgets, provenance framing, the
signed log, the lease. Your plugin translates one platform's wire; it never
sees the keystore, the manifest, or any other agent's material.

## Methods

### `initialize` (request)

First message, always. The host passes the manifest presence entry's config
and — at the instant of use — the plaintext of the credential the human
sealed to the agent when declaring the channel.

```json
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{
     "protocol":"apiary-channel/1",
     "config":{"room":"#general"},
     "credential":"platform-token-or-null"}}
← {"jsonrpc":"2.0","id":1,"result":{"name":"my-platform","kind":"my-platform"}}
```

Return an `error` instead of a `result` to refuse (bad config, bad token);
the host reports it and retries with backoff.

### `poll` (request)

Long-poll your platform for up to `timeout_ms`. Return every message that
should ENGAGE the agent (your platform's notion of a mention or DM — apply
your own trigger and allowlist rules here). An empty list is a quiet tick;
the host uses ticks for lease heartbeats, so honor the timeout rather than
spinning.

```json
→ {"jsonrpc":"2.0","id":2,"method":"poll","params":{"timeout_ms":15000}}
← {"jsonrpc":"2.0","id":2,"result":{"mentions":[
     {"ref":"msg-77","channel":"#general","author":"alice","text":"@agent hi"}]}}
```

`ref` is yours: an opaque string the host echoes back in `reply` so you can
thread the response (message id, thread ts, whatever your platform needs).

A mention may carry an optional `attachments` array when the platform
message had media — download it yourself, base64-encode, and cap sensibly
(the host keeps at most 4, 5 MB each, and budgets tokens for each):

```json
{"ref":"msg-79","channel":"#general","author":"alice",
 "text":"@agent what plant is this?",
 "attachments":[
   {"kind":"image","media_type":"image/jpeg","base64":"/9j/4AAQ…"},
   {"kind":"audio","media_type":"audio/ogg","base64":"T2dnUw…","duration_secs":4.2}
 ]}
```

`kind` is `image` or `audio` (unknown kinds are dropped, not fatal). Images
reach vision-capable models; audio is transcribed host-side when the agent
declares a `transcribe` slot, and honestly reported as unheard otherwise.
The older `images: [{media_type, base64}]` spelling is still accepted as an
alias for one release. Omitting the field (or sending `[]`) is always
valid — text-only plugins need no changes.

### `reply` (request)

Deliver the agent's governed reply where the mention lives.

```json
→ {"jsonrpc":"2.0","id":3,"method":"reply","params":{"ref":"msg-77","text":"hello!"}}
← {"jsonrpc":"2.0","id":3,"result":{"id":"msg-78"}}
```

When the agent's presence entry says `reply_as: voice` (or `match`, and the
mention carried audio) and the host has a `speak` slot, `params` also carries
the synthesized speech — deliver it as a voice message if your platform has
one, and always deliver `text` too (caption or body): the words are the
record, the audio is a rendering.

```json
{"ref":"msg-77","text":"hello!",
 "audio":{"media_type":"audio/ogg","base64":"T2dnUw…","duration_secs":1.8}}
```

Plugins that ignore `audio` remain correct.

### `shutdown` (notification)

No id, no response expected: exit promptly. The host escalates to SIGKILL
after a grace period, and also treats closed stdin as shutdown.

## Installing a plugin

Drop the executable anywhere and register it host-side in
`<APIARY_HOME>/plugins.yaml`:

```yaml
plugins:
  - name: my-platform
    protocol: apiary-channel/1
    command: /usr/local/bin/apiary-my-platform
    args: []
```

An agent then declares it like any channel — in the manifest (ratified,
like all presence) or the cockpit's "Declare presence" form:

```yaml
presence:
  my-platform:
    credential: <nip44-sealed token>   # arrives at initialize, decrypted
    room: "#general"                   # everything else is your config
```

While the agent is ACTIVE, the supervisor runs your plugin alongside the
other channels — restarted if it dies, bounced when the manifest changes,
stopped on deactivation, all under the agent's single lease.

## Trust model, honestly

Installing a plugin is installing code, host-trusted like an MCP server.
The protocol confines what a plugin is *given*, not what it *is*: it
receives one platform credential and a config map, and its replies are
whatever the governed run produced. A malicious plugin can misbehave on
its own platform; it cannot exceed the agent's constitution, reach other
credentials, or bypass the spend ledger.

## A complete plugin in ~40 lines of Python

```python
#!/usr/bin/env python3
# apiary-channel/1 reference: echoes one scripted mention, logs replies.
import json, sys, time

def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n"); sys.stdout.flush()

polls = 0
for line in sys.stdin:
    try: req = json.loads(line)
    except ValueError: continue
    rid, method, p = req.get("id"), req.get("method"), req.get("params", {})
    if method == "initialize":
        # p["credential"] is your platform token; p["config"] your settings.
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"name": "demo", "kind": "demo"}})
    elif method == "poll":
        polls += 1
        mentions = []
        if polls == 2:   # a real plugin long-polls its platform here
            mentions = [{"ref": "m1", "channel": "demo-room",
                         "author": "alice", "text": "@agent hello"}]
        else:
            time.sleep(min(p.get("timeout_ms", 15000), 2000) / 1000)
        send({"jsonrpc": "2.0", "id": rid, "result": {"mentions": mentions}})
    elif method == "reply":
        print(f"delivered: {p['text']!r} (re {p['ref']})", file=sys.stderr)
        send({"jsonrpc": "2.0", "id": rid, "result": {"id": "demo-1"}})
    elif method == "shutdown":
        break
```

The Rust reference implementation ships in this repo as the
`mock-channel` binary (`crates/apiary-runtime/src/bin/mock-channel.rs`)
and is exercised by the test suite over a real subprocess.
