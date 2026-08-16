// Apiary cockpit. All dynamic strings render through textContent — agent
// names, log fields, model output, tool args, and errors are DATA, and the
// governance origin never interprets data as markup. (CSP backs this up:
// no inline script, no external sources.)
'use strict';

let sel = null, tab = 'overview', agents = [], hostStatus = {};
let hostView = false;
let listenerPoll = null;

// Desktop mode hands the per-launch token in the boot URL; every API call
// echoes it back in a header. Without a token this is a no-op.
const TOKEN = new URLSearchParams(location.search).get('token');
function hdrs(extra) {
  const h = Object.assign({}, extra);
  if (TOKEN) h['x-apiary-token'] = TOKEN;
  return h;
}
async function j(url, opts) {
  opts = opts || {};
  opts.headers = hdrs(opts.headers);
  const r = await fetch(url, opts);
  return r.json();
}

// el('div', 'cls', 'text') — safe node construction.
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
function help(text) { return el('div', 'help', text); }
function kv(k, v) {
  const row = el('div', 'kv');
  row.append(el('span', 'k', k), el('span', 'v', v === undefined || v === null ? '—' : String(v)));
  return row;
}
function section(title, helpText) {
  const s = el('div', 'section');
  s.append(el('h3', null, title));
  if (helpText) s.append(help(helpText));
  return s;
}
function api(path) { return `/api/agents/${encodeURIComponent(sel)}${path}`; }

// ------------------------------------------------------------ host status

async function loadStatus() {
  try { hostStatus = await j('/api/status'); } catch { hostStatus = {}; }
  const set = (id, text, cls) => {
    const n = document.getElementById(id);
    n.textContent = text;
    if (cls !== undefined) n.className = cls;
  };
  set('c-ver', 'v' + (hostStatus.version || '?'));
  document.getElementById('c-home').title = 'state directory: ' + (hostStatus.home || '?');
  set('c-auth', 'auth ' + (hostStatus.auth || '?') + (hostStatus.token_gated ? ' +token' : ''));
  set('c-model', hostStatus.anthropic_key_present ? 'model key ✓' : 'model key —',
      'chip ' + (hostStatus.anthropic_key_present ? 'ok' : ''));
  document.getElementById('c-model').title = hostStatus.anthropic_key_present
    ? 'ANTHROPIC_API_KEY present in the host environment'
    : 'no ANTHROPIC_API_KEY in the host environment — anthropic-routed runs and model drafting will refuse';
  set('c-lock', hostStatus.unlocked ? 'unlocked' : 'LOCKED — click to unlock',
      'chip click ' + (hostStatus.unlocked ? 'ok' : 'bad'));
  // Once unlocked, never ask again: the passphrase prompt disappears and
  // the bar only offers LOCK.
  const unlocked = !!hostStatus.unlocked;
  document.getElementById('u-pass').style.display = unlocked ? 'none' : '';
  document.getElementById('u-go').style.display = unlocked ? 'none' : '';
  document.getElementById('u-help').textContent = unlocked
    ? 'keystore unlocked for this session — LOCK to forget the passphrase'
    : 'passphrase unlocks the NIP-49 keystore for this session — needed to run, ratify, found, post, seal:';
}

document.getElementById('c-lock').onclick = () => {
  const b = document.getElementById('unlockbar');
  b.style.display = b.style.display === 'flex' ? 'none' : 'flex';
};
document.getElementById('c-keytool').onclick = () => {
  const b = document.getElementById('keybar');
  b.style.display = b.style.display === 'flex' ? 'none' : 'flex';
};
document.getElementById('u-go').onclick = async () => {
  const st = document.getElementById('u-status');
  st.textContent = 'unlocking… (NIP-49 scrypt is deliberately slow)';
  const r = await j('/api/unlock', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ passphrase: document.getElementById('u-pass').value }),
  });
  st.textContent = r.ok
    ? (r.verified_against_key ? 'unlocked ✓ (verified against a stored key)' : 'unlocked ✓ (empty keystore — nothing to verify against)')
    : 'refused: ' + r.error;
  if (r.ok) {
    document.getElementById('u-pass').value = '';
    setTimeout(() => { document.getElementById('unlockbar').style.display = 'none'; }, 1200);
  }
  loadStatus();
};
document.getElementById('u-lock').onclick = async () => {
  await j('/api/lock', { method: 'POST' });
  document.getElementById('u-status').textContent = 'locked — passphrase forgotten';
  loadStatus();
};
document.getElementById('k-go').onclick = async () => {
  const r = await j('/api/key?key=' + encodeURIComponent(document.getElementById('k-in').value.trim()));
  document.getElementById('k-out').textContent = r.ok ? `${r.npub} · ${r.hex}` : 'invalid: ' + r.error;
};

// ------------------------------------------------------------ roster

async function loadRoster() {
  const d = await j('/api/agents');
  agents = d.agents || [];
  const root = document.getElementById('roster');
  root.replaceChildren();
  if (!agents.length) root.append(el('div', 'empty', 'no agents in this keystore'));
  const running = new Set((hostStatus.listeners || []).filter(l => l.running).map(l => l.npub));
  for (const a of agents) {
    const card = el('div', 'agent' + (sel === a.npub ? ' sel' : ''));
    const nm = el('div', 'nm', a.name || '(unnamed)');
    nm.append(el('span', 'badge ' + (a.ratified ? 'rat' : 'unrat'), a.ratified ? 'ratified' : 'unratified'));
    nm.append(el('span', 'badge ' + (a.active ? 'live' : 'unrat'), a.active ? 'active' : 'inactive'));
    if (running.has(a.npub)) nm.append(el('span', 'badge live', 'listening'));
    card.append(nm, el('div', 'np', a.npub), el('div', 'np', a.log_entries + ' log entries'));
    card.onclick = () => { hostView = false; sel = a.npub; render(); loadRoster(); };
    root.append(card);
  }
}

document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  hostView = false;
  tab = b.dataset.tab;
  document.querySelectorAll('nav button').forEach(x => x.classList.toggle('sel', x === b));
  render();
});

function entryLine(bold, rest, metaLines) {
  const div = el('div', 'entry');
  div.append(el('b', null, bold));
  if (rest) div.append(document.createTextNode(' ' + rest));
  for (const m of metaLines || []) div.append(el('div', 'meta', m));
  return div;
}

// ------------------------------------------------------------ tabs

async function render() {
  if (listenerPoll) { clearInterval(listenerPoll); listenerPoll = null; }
  // Agent tabs only make sense when looking at an agent.
  document.querySelector('nav').style.display = (hostView || !sel) ? 'none' : 'flex';
  const c = document.getElementById('content');
  c.replaceChildren();
  if (hostView) return renderLibrary(c);
  if (!sel) { c.append(el('div', 'empty', 'select an agent — or open the host connector library from the sidebar')); return; }
  if (tab === 'overview') return renderOverview(c);
  if (tab === 'run') return renderRun(c);
  if (tab === 'log') return renderLog(c);
  if (tab === 'manifest') return renderManifest(c);
  if (tab === 'buzz') return renderBuzz(c);
  if (tab === 'connectors') return renderConnectors(c);
  if (tab === 'creds') return renderCreds(c);
}

// ------------------------------------------------------------ overview

async function renderOverview(c) {
  const d = await j(api('/manifest'));
  if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }
  const m = d.manifest || {};
  const gov = m.governance || {};

  const roster = agents.find(a => a.npub === sel) || {};
  const idSec = section('Identity',
    'The agent IS this keypair. The npub is public and portable — Buzz membership, log signatures, and published memory all bind to it. The private half never leaves the NIP-49 keystore on this host.');
  idSec.append(kv('npub', sel));
  const keyRow = await j('/api/key?key=' + encodeURIComponent(sel));
  if (keyRow.ok) idSec.append(kv('hex', keyRow.hex));
  idSec.append(kv('ratified', d.ratified ? 'yes — constitution in force' : 'NO — nothing runs unratified'));
  idSec.append(kv('manifest sha256', d.manifest_sha256));
  const rnRow = el('div', 'row');
  const rnIn = el('input'); rnIn.placeholder = 'new label'; rnIn.value = roster.name || '';
  const rnGo = el('button', 'btn', 'RENAME');
  const rnSt = el('span', 'meta', '');
  rnRow.append(rnIn, rnGo, rnSt);
  idSec.append(rnRow, help('The label is host-local and for humans — the identity is the keypair. The Buzz display name (kind-0 profile) is published separately from the Buzz tab; a running listener keeps its old @trigger until restarted.'));
  rnGo.onclick = async () => {
    const r = await j(api('/name'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: rnIn.value.trim() }),
    });
    rnSt.textContent = r.ok ? 'renamed ✓' : 'refused: ' + r.error;
    loadRoster();
  };
  c.append(idSec);

  const actSec = section('Activation',
    'Host-local operator switch — deliberately not part of the constitution. While ACTIVE, this host supervises the agent’s declared standing presence: if the manifest declares presence.buzz, the mention listener runs, restarts if it dies, and stops on deactivation. Inactive agents hold no standing presence; one-shot runs stay available either way.');
  actSec.append(kv('state', roster.active ? 'ACTIVE' : 'inactive'));
  actSec.append(kv('presence.buzz', roster.buzz_declared ? 'declared in manifest — supervised' : 'not declared — nothing to supervise (see the Manifest field guide)'));
  const actRow = el('div', 'row');
  const actBtn = el('button', 'btn' + (roster.active ? ' danger' : ' solid'), roster.active ? 'DEACTIVATE' : 'ACTIVATE');
  const actSt = el('span', 'meta', '');
  actRow.append(actBtn, actSt);
  actSec.append(actRow);
  actBtn.onclick = async () => {
    const r = await j(api('/active'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ active: !roster.active }),
    });
    actSt.textContent = r.ok ? r.note : 'failed: ' + r.error;
    await loadRoster(); render();
  };
  c.append(actSec);

  const portSec = section('Portability',
    'The agent IS manifest + key + signed log + semantic index — this exports ALL of it as one verified bundle, recall included: the imported agent needs nothing rebuilt and no matching embedding model. The key inside stays NIP-49-locked; share the passphrase out of band, never alongside the file. Import on the other host verifies the key, manifest, every signature, the chain, and ratification before anything lands; the agent arrives INACTIVE and the lease referees the switchover: export → import there → deactivate here → activate there.');
  const pRow2 = el('div', 'row');
  const exPass = el('input'); exPass.type = 'password';
  exPass.placeholder = 'handoff passphrase (optional)';
  const exTo = el('input', 'grow'); exTo.placeholder = 'or seal to recipient npub (optional)';
  const exBtn = el('button', 'btn', 'EXPORT BUNDLE');
  const exStat = el('span', 'meta', '');
  pRow2.append(exPass, exTo, exBtn, exStat);
  portSec.append(pRow2, help('Three modes, none required: plain (for your own hosts), handoff passphrase (zero recipient setup — share the secret out of band), or SEALED to a recipient npub — a kind-4602 envelope signed by the agent and encrypted so only that key opens it: no secret in flight, tamper- and truncation-evident, safe over any channel. The recipient needs that key in their keystore. To hand over governance too, first amend suspend_keys to include the recipient and ratify — the key lets them act AS the agent, only a listed suspend key can amend its constitution.'));
  exBtn.onclick = async () => {
    if (exPass.value && exTo.value) { exStat.textContent = 'choose ONE: passphrase or npub'; return; }
    exStat.textContent = (exPass.value || exTo.value) ? 'unlocking + sealing…' : 'exporting…';
    const r = await j(api('/export'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ export_passphrase: exPass.value || null, to_npub: exTo.value.trim() || null }) });
    exPass.value = ''; exTo.value = '';
    exStat.textContent = r.ok
      ? (r.sealed_to ? `sealed to ${r.sealed_to.slice(0, 16)}… → ${r.path}` : `saved: ${r.path} (${r.log_entries} log entries, ${r.index_rows} index rows${r.handoff_passphrase ? ', handoff-locked' : ''})`)
      : 'failed: ' + r.error;
  };
  c.append(portSec);

  const govSec = section('Governance',
    'Suspend keys are the human governors: only they ratify, and any of them can suspend. Ratification = the agent signs its manifest hash AND a suspend-key holder countersigns; both land in the public log. Editing the manifest changes the hash, which suspends the agent until re-ratified.');
  for (const k of (gov.suspend_keys || [])) govSec.append(kv('suspend key', k));
  const budget = (gov.budgets || {}).tokens_per_day;
  govSec.append(kv('tokens_per_day', budget !== undefined ? budget + ' (hard ceiling)' : 'none set — runs reserve a bounded default'));
  const spend = await j(api('/spend'));
  if (spend.ok) {
    govSec.append(kv('spent today (' + spend.date + ')', `${spend.used} used · ${spend.reserved} reserved` + (spend.remaining !== null && spend.remaining !== undefined ? ` · ${spend.remaining} remaining` : '')));
    if (spend.budget_tokens_per_day) {
      const bar = el('div', 'bar'); const fill = el('div');
      const frac = Math.min(1, (spend.used + spend.reserved) / spend.budget_tokens_per_day);
      fill.style.width = (frac * 100).toFixed(1) + '%';
      if (frac > 0.85) fill.className = 'hot';
      bar.append(fill); govSec.append(bar);
      govSec.append(help('The budget is enforced by atomic reservations taken before each model call — a run that would exceed it is refused, not trimmed.'));
    }
  }
  c.append(govSec);

  const infSec = section('Inference pool & routing',
    'Models are slots, not identity — "inference in, connections out". The routing table picks a slot per task class; human-set floors clamp what routing may choose (stricter than the floor is allowed, looser never).');
  for (const slot of (m.inference || [])) infSec.append(kv(slot.name, `${slot.provider} / ${slot.model}`));
  if (!(m.inference || []).length) infSec.append(kv('pool', 'empty — this agent cannot run'));
  const routing = m.routing || {};
  if (routing.default) infSec.append(kv('routing.default', routing.default));
  for (const r of (routing.rules || [])) infSec.append(kv('rule', JSON.stringify(r)));
  for (const f of (routing.floors || [])) infSec.append(kv('floor', JSON.stringify(f)));
  c.append(infSec);

  const conSec = section('Connectors',
    'Everything the agent can touch is a connector, declared here and default-deny at runtime. Credentials are NIP-44-sealed to the agent’s own key (see the Credentials tab) — a manifest dump is not a credential dump.');
  for (const con of (m.connectors || [])) conSec.append(kv(con.name || con.type || '?', JSON.stringify(con.caps || {})));
  if (!(m.connectors || []).length) conSec.append(kv('connectors', 'none — the agent can think and speak, not act'));
  conSec.append(help('Grant and revoke in the Connectors tab: definitions are configured once at host level, grants are per-agent manifest amendments (ratified, portable).'));
  c.append(conSec);

  const mem = m.memory || {};
  const memSec = section('Memory',
    'Three tiers by sensitivity: public log entries publish to relays as-is; self-tier entries publish encrypted to the agent’s own key (portable but stranger-proof); local never leaves this machine. The semantic index embeds the log for retrieval into the working set.');
  memSec.append(kv('log tier default', mem.log));
  memSec.append(kv('index', mem.index));
  for (const r of (mem.log_relays || [])) memSec.append(kv('log relay', r));
  if (!(mem.log_relays || []).length) memSec.append(kv('log relays', 'none — publishing disabled until added to the manifest'));
  c.append(memSec);

  const lease = m.lease || {};
  const leaseSec = section('Lease',
    'Which host may run this agent’s standing presence. The running host heartbeats an agent-signed lease event on the log relays; a second host refuses to start while a live foreign lease exists. Takeover policy "contested-human": superseding a live lease is a button a person presses, never something hosts do on their own. One-shot runs are not lease-gated.');
  leaseSec.append(kv('mechanism / takeover', (lease.mechanism || 'relay-event') + ' / ' + (lease.takeover || 'contested-human')));
  leaseSec.append(kv('heartbeat / expiry', (lease.heartbeat_secs || '—') + 's / ' + (lease.expiry_secs || '—') + 's'));
  const leaseLine = kv('current lease', 'checking relays…');
  leaseSec.append(leaseLine);
  const toRow = el('div', 'row'); toRow.style.display = 'none';
  const toBtn = el('button', 'btn danger', 'TAKE OVER (HUMAN DECISION)');
  const toSt = el('span', 'meta', '');
  toRow.append(toBtn, toSt);
  leaseSec.append(toRow);
  c.append(leaseSec);
  j(api('/lease')).then(lz => {
    if (!lz.ok) { leaseLine.replaceChildren(el('span','k','current lease'), el('span','v','error: ' + lz.error)); return; }
    if (!lz.coordinated) {
      leaseLine.replaceChildren(el('span','k','current lease'), el('span','v', lz.note));
      return;
    }
    if (!lz.lease) {
      leaseLine.replaceChildren(el('span','k','current lease'), el('span','v', 'none on the relays — first active host claims it (this host: ' + lz.host_id + ')'));
      return;
    }
    const l = lz.lease;
    const until = new Date(l.expires_at * 1000).toLocaleTimeString();
    let text;
    if (l.ours) text = `held by THIS host (${l.holder}) · seq ${l.seq} · renews until ${until}`;
    else if (l.expired) text = `expired lease from host ${l.holder} — this host may claim it freely`;
    else { text = `HELD BY ANOTHER HOST (${l.holder}) · seq ${l.seq} · expires ${until}`; toRow.style.display = 'flex'; }
    leaseLine.replaceChildren(el('span','k','current lease'), el('span','v', text));
  });
  toBtn.onclick = async () => {
    toSt.textContent = 'taking over…';
    const r = await j(api('/lease/takeover'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    toSt.textContent = r.ok ? r.note : 'failed: ' + r.error;
  };

  const lisSec = section('Presence channels',
    'Everywhere the agent LIVES — each channel declared in the manifest (ratified), all supervised together under one lease while the agent is ACTIVE. Declare channels below or in the manifest; this panel is live.');
  const chanBox = el('div');
  lisSec.append(chanBox);
  c.append(lisSec);
  const updateListener = async () => {
    const l = await j(api('/listener'));
    if (!l.ok) return;
    chanBox.replaceChildren();
    if (!(l.declared || []).length) {
      chanBox.append(kv('channels', 'none declared — nothing to supervise (declare below, see the field guide, or use the Buzz tab)'));
    }
    for (const kind of (l.declared || [])) {
      const ch = (l.channels || {})[kind] || {};
      let status = ch.running ? 'running' : (ch.note || (roster.active ? (hostStatus.unlocked ? 'starting (supervisor ~10s, retry 30s)' : 'waiting — keystore locked') : 'inactive — activate above'));
      const row = kv(kind, status);
      const stopB = el('button', 'btn danger', 'STOP');
      stopB.style.marginLeft = '8px';
      stopB.style.display = ch.running ? '' : 'none';
      stopB.onclick = async () => { await j(api('/listener?channel=' + encodeURIComponent(kind)), { method: 'DELETE' }); updateListener(); };
      row.append(stopB);
      chanBox.append(row);
      if ((ch.lines || []).length) {
        const pre = el('pre'); pre.textContent = ch.lines.slice(-6).join('\n');
        chanBox.append(pre);
      }
    }
    if (l.lease_keeper) {
      chanBox.append(kv('lease keeper', l.lease_keeper.lost ? 'LOST — see Lease section' : (l.lease_keeper.running ? 'holding the lease' : 'stopped')));
    } else if ((l.declared || []).length) {
      chanBox.append(kv('lease keeper', l.supervisor_note || 'not running'));
    }
  };
  updateListener();
  listenerPoll = setInterval(updateListener, 3000);

  // Declare-a-channel forms: telegram + slack (buzz has its tab; plugins
  // declare with the generic form).
  const decSec = section('Declare presence',
    'Declaring a channel writes it into the manifest with the platform secret NIP-44-sealed to this agent — an amendment, so re-ratify after. Telegram: a BotFather token + allowed chat ids (["*"] admits anyone, deliberately). Slack: a Socket-Mode app token AND bot token as JSON {"app_token":"xapp-…","bot_token":"xoxb-…"} + optional allowed channel ids. Plugins installed on this host declare by their name with config JSON.');
  const dKind = el('select');
  for (const k of ['telegram', 'slack', 'buzz']) { const o = el('option', null, k); o.value = k; dKind.append(o); }
  const dCred = el('input', 'grow'); dCred.type = 'password'; dCred.placeholder = 'platform secret (token / JSON) — sealed to the agent';
  const dConf = el('input', 'grow'); dConf.placeholder = 'config JSON (e.g. {"allowed_chats":["123"]} or {"relay":"wss://…"})';
  const dGo = el('button', 'btn solid', 'DECLARE');
  const dSt = el('span', 'meta', '');
  const dRow = el('div', 'row'); dRow.append(dKind, dCred, dConf, dGo, dSt);
  decSec.append(dRow);
  c.append(decSec);
  dGo.onclick = async () => {
    let config = {};
    if (dConf.value.trim()) {
      try { config = JSON.parse(dConf.value); } catch { dSt.textContent = 'config is not valid JSON'; return; }
    }
    dSt.textContent = 'sealing + declaring…';
    const r = await j(api('/presence'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ kind: dKind.value, credential: dCred.value || null, config }),
    });
    dCred.value = '';
    dSt.textContent = r.ok ? `declared ${r.declared} — re-ratify in the Manifest tab` : 'refused: ' + r.error;
    if (r.ok) loadRoster();
  };
}

// ------------------------------------------------------------ run

function renderRun(c) {
  c.append(help('One governed task. The stream below is AG-UI presence (steps, tool calls, text); the signed log is truth — every model call lands as a signed checkpoint entry. Budget reservations are taken before the call and settled after.'));
  const box = el('div'); box.id = 'runbox';
  const ta = el('textarea'); ta.id = 'task'; ta.placeholder = 'task for this agent…';
  const go = el('button', null, 'RUN'); go.id = 'go';
  box.append(ta, go);
  const row = el('div', 'row');
  const cls = el('input'); cls.placeholder = 'class (optional, e.g. reasoning)';
  const dcls = el('input'); dcls.placeholder = 'data class (optional, e.g. sensitive)';
  row.append(cls, dcls);
  c.append(box, row,
    help('class picks a routing rule from the manifest (which model slot handles this kind of task). data class engages routing floors — e.g. a "sensitive" floor can pin such tasks to a local model regardless of what routing would prefer.'));
  const events = el('div'); events.id = 'events';
  c.append(events);
  go.onclick = () => runTask(ta, go, events, cls.value.trim() || null, dcls.value.trim() || null);
}

function ev(events, cls, text) {
  events.prepend(el('div', 'ev ' + cls, text));
}

async function runTask(ta, go, events, cls, dcls) {
  const task = ta.value.trim();
  if (!task) return;
  go.disabled = true;
  events.replaceChildren();
  try {
    const resp = await fetch(api('/run'), {
      method: 'POST',
      headers: hdrs({ 'content-type': 'application/json' }),
      body: JSON.stringify({ task, class: cls, data_class: dcls }),
    });
    if (!resp.ok) {
      let msg = String(resp.status);
      try { msg = (await resp.json()).error || msg; } catch {}
      ev(events, 'err', 'refused: ' + msg);
      go.disabled = false;
      return;
    }
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const frame = buf.slice(0, i); buf = buf.slice(i + 2);
        const line = frame.split('\n').find(l => l.startsWith('data:'));
        if (!line) continue;
        let e; try { e = JSON.parse(line.slice(5)); } catch { continue; }
        switch (e.type) {
          case 'RUN_STARTED': ev(events, 'meta', 'run started · ' + e.runId); break;
          case 'STEP_STARTED': ev(events, 'step', '⚙ ' + e.stepName); break;
          case 'TOOL_CALL_START': ev(events, 'tool', '⚒ tool: ' + e.toolCallName); break;
          case 'TOOL_CALL_ARGS': ev(events, 'meta', 'args ' + e.delta); break;
          case 'TOOL_CALL_END': ev(events, e.ok ? 'tool' : 'err', `⚒ ${e.toolCallId} ${e.ok ? 'ok' : 'FAILED'} — ${e.detail}`); break;
          case 'TEXT_MESSAGE_CONTENT': ev(events, 'text', e.delta); break;
          case 'CUSTOM':
            if (e.name === 'apiary.checkpoint') {
              const v = e.value;
              ev(events, 'meta', `✓ signed checkpoint ${v.log_event} · ${v.model} · ${v.input_tokens}in/${v.output_tokens}out`);
            }
            break;
          case 'RUN_FINISHED': ev(events, 'meta', 'run finished'); loadRoster(); break;
          case 'RUN_ERROR': ev(events, 'err', e.message); break;
        }
      }
    }
  } catch (err) { ev(events, 'err', String(err)); }
  go.disabled = false;
}

// ------------------------------------------------------------ log

async function renderLog(c) {
  const d = await j(api('/log?tail=100'));
  if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }
  const chain = d.chain.valid ? `chain valid · ${d.chain.entries} entries` : `CHAIN BROKEN: ${d.chain.error}`;
  c.append(entryLine('signed log', chain));
  c.append(help('Every entry is a signed nostr event chained to the previous one — the agent’s tamper-evident memory and audit trail in one. "chain valid" means every signature verifies and no entry was removed or reordered.'));

  const row = el('div', 'row');
  const pub = el('button', 'btn', 'PUBLISH TO RELAYS');
  const rem = el('button', 'btn', 'FETCH REMOTE COPY');
  const st = el('span', 'meta', '');
  row.append(pub, rem, st);
  c.append(row, help('Publish pushes the log to the manifest’s memory.log_relays, tier-enforced: public entries go as-is, self-tier entries go NIP-44-encrypted to the agent’s own key (anyone can store them, only the agent can read them), local-tier entries never leave. Fetch pulls the published copy back, verifies signatures, and decrypts the agent’s own wrapped entries — proof the memory is truly portable.'));

  const out = el('div');
  c.append(out);
  pub.onclick = async () => {
    st.textContent = 'publishing…';
    const r = await j(api('/log/publish'), { method: 'POST' });
    st.textContent = r.ok
      ? `published: ${r.published_public} public, ${r.published_wrapped} wrapped · ${r.skipped_local} local kept back · ${r.already_published} already up`
      : 'failed: ' + r.error;
  };
  rem.onclick = async () => {
    st.textContent = 'fetching…';
    out.replaceChildren();
    const r = await j(api('/log/remote'));
    st.textContent = r.ok ? 'fetched' : 'failed: ' + r.error;
    if (!r.ok) return;
    for (const relay of (r.relays || [])) {
      out.append(entryLine(relay.relay, relay.ok ? `${(relay.events || []).length} events` : 'unreachable: ' + relay.error));
      for (const e of (relay.events || []).slice(0, 30)) {
        const b = e.body || {};
        out.append(entryLine(b.action || (e.wrapped ? '(wrapped)' : '?'), '→ ' + (b.outcome || ''), [
          new Date(e.at * 1000).toLocaleString() + (e.wrapped ? ' · self-tier (decrypted locally)' : ' · public'),
          e.id,
        ]));
      }
    }
  };

  for (const e of (d.entries || []).slice().reverse()) {
    const b = e.body || {};
    const meta = [
      new Date(e.at * 1000).toLocaleString()
        + (b.model ? ' · ' + b.model : '')
        + (b.harness ? ' · ' + b.harness : '')
        + (b.cost ? ` · ${b.cost.input_tokens}in/${b.cost.output_tokens}out` : ''),
      e.id,
    ];
    c.append(entryLine(b.action || '?', '→ ' + (b.outcome || '?'), meta));
  }
}

// ------------------------------------------------------------ manifest

async function renderManifest(c) {
  const d = await j(api('/manifest'));
  if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }
  const status = d.ratified ? 'ratified' : 'NOT ratified — amend freely, then ratify';
  c.append(entryLine('sha256', d.manifest_sha256 + ' — ' + status));
  c.append(help('The manifest is the agent’s constitution: identity, model pool, routing, connectors, memory, governance, lease. Saving an amendment changes the hash, which automatically suspends the agent until a suspend-key holder re-ratifies — amendments are cheap, unratified amendments are inert.'));

  const guide = el('details');
  guide.append(el('summary', null, 'field guide — what every setting does'));
  const g = el('div');
  const rows = [
    ['identity.npub', 'the agent’s public key — immutable; the host refuses an amendment that changes it'],
    ['inference[]', 'the model pool: named slots {name, provider, model}. Providers: anthropic (API key from host env), ollama (local), mock (tests). An "embed" slot powers the semantic index.'],
    ['routing.default', 'slot used when no rule matches'],
    ['routing.rules[]', 'per-task-class slot choices, e.g. {class: reasoning, use: workhorse}'],
    ['routing.floors[]', 'human-owned clamps, e.g. {data_class: sensitive, require_provider: ollama} — routing may be stricter than a floor, never looser'],
    ['connectors[]', 'what the agent may touch, default-deny. Each entry: {type, caps, credential?}. Managed from the Connectors tab: host library holds configurations, grants are per-agent amendments with credentials sealed to this agent alone.'],
    ['memory.log', 'default tier for new log entries: public | self | local'],
    ['memory.index', 'semantic index location (local)'],
    ['memory.log_relays[]', 'nostr relays the log publishes to (tier-enforced)'],
    ['presence.buzz', 'standing workspace membership: {relay, trigger?}. Constitutional — where the agent lives is ratified. While the agent is ACTIVE (Overview), the host supervises its mention listener.'],
    ['governance.suspend_keys[]', 'human governor npubs — ratifiers; at least one required'],
    ['governance.budgets.tokens_per_day', 'hard daily token ceiling, enforced by atomic reservations'],
    ['lease', 'which host runs the agent: relay-event heartbeats, takeover policy (contested-human = a person resolves disputes), timings'],
  ];
  for (const [k, v] of rows) g.append(kv(k, v));
  guide.append(g);
  c.append(guide);

  const ed = el('textarea'); ed.id = 'med'; ed.spellcheck = false; ed.value = d.yaml;
  const row = el('div', 'row');
  const save = el('button', 'btn', 'SAVE AMENDMENT');
  const who = el('select');
  const holders = agents.filter(a => (d.manifest.governance.suspend_keys || []).some(k => k.includes(a.npub) || a.npub.includes(k)));
  if (holders.length) {
    for (const h of holders) {
      const o = el('option', null, h.name || h.npub.slice(0, 16));
      o.value = h.npub; who.append(o);
    }
  } else {
    who.append(el('option', null, 'no keystore-held suspend key'));
  }
  const rat = el('button', 'btn solid', 'RATIFY');
  const status2 = el('span', 'meta', '');
  row.append(save, el('span', 'meta', 'ratify as:'), who, rat, status2);
  c.append(ed, row);
  c.append(help('Ratify signs twice: the agent signs its manifest hash, then the selected human key countersigns. Both events land in the public log — the founding ceremony, repeated for every amendment.'));
  save.onclick = async () => {
    const r = await j(api('/manifest'), {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ yaml: ed.value }),
    });
    status2.textContent = r.ok ? `saved · ${r.manifest_sha256.slice(0, 12)}… · re-ratify to run` : `rejected: ${r.error}`;
    loadRoster();
  };
  rat.onclick = async () => {
    if (!who.value || !who.value.startsWith('npub')) return;
    status2.textContent = 'ratifying… (two NIP-49 key loads; slow by design)';
    const r = await j(api('/ratify'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ as: who.value }),
    });
    status2.textContent = r.ok ? 'ratified ✓ both signatures in the log' : `refused: ${r.error}`;
    loadRoster(); if (r.ok) render();
  };

  const ext = el('details');
  ext.append(el('summary', null, 'external ratification — sign with a key that never enters Apiary'));
  const extBody = el('div');
  extBody.append(help('For governors who keep their master nostr key outside this host: export the unsigned ratification event, sign it with your own tooling (nak, a NIP-07 extension, a signer app), and import the signed event. The keystore never sees the key.'));
  const exRow = el('div', 'row');
  const exKey = el('input', 'grow'); exKey.placeholder = 'external governor key (npub or hex, must be a listed suspend key)';
  const exGo = el('button', 'btn', 'EXPORT UNSIGNED EVENT');
  exRow.append(exKey, exGo);
  const exOut = el('pre'); exOut.style.display = 'none';
  const imRow = el('div', 'row');
  const imIn = el('textarea'); imIn.rows = 4; imIn.placeholder = 'paste the signed event JSON here';
  const imGo = el('button', 'btn', 'IMPORT SIGNED EVENT');
  const exSt = el('span', 'meta', '');
  imRow.append(imGo, exSt);
  extBody.append(exRow, exOut, imIn, imRow);
  ext.append(extBody);
  c.append(ext);
  exGo.onclick = async () => {
    const r = await j(api('/ratify/export'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ as: exKey.value.trim() }),
    });
    exOut.style.display = 'block';
    exOut.textContent = r.ok ? JSON.stringify(r.unsigned_event, null, 2) : 'refused: ' + r.error;
  };
  imGo.onclick = async () => {
    let evj;
    try { evj = JSON.parse(imIn.value); } catch { exSt.textContent = 'not valid JSON'; return; }
    exSt.textContent = 'importing…';
    const r = await j(api('/ratify/import'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: evj }),
    });
    exSt.textContent = r.ok ? 'imported ✓ ratified by ' + r.ratified_by.slice(0, 12) + '…' : 'refused: ' + r.error;
    loadRoster(); if (r.ok) render();
  };
}

// ------------------------------------------------------------ buzz

function relayInput() {
  const inp = el('input', 'grow');
  inp.placeholder = 'wss://your-buzz-relay';
  inp.value = localStorage.getItem('apiary.relay') || '';
  inp.onchange = () => localStorage.setItem('apiary.relay', inp.value.trim());
  return inp;
}

async function renderBuzz(c) {
  c.append(help('Buzz is a nostr-native agent workspace — and structurally just a relay, so the agent joins with its own key (NIP-42 auth), not a bot token. Everything here acts AS the selected agent and logs to its signed history.'));

  const relaySec = section('Workspace relay', 'The Buzz relay URL. Membership is admitted relay-side (buzz-admin); until admitted, operations will be refused politely.');
  const relay = relayInput();
  relaySec.append(relay);
  c.append(relaySec);
  const rv = () => relay.value.trim();

  const profSec = section('Profile',
    'Publishes a kind-0 profile so the workspace shows a name instead of a hex key. Also lands in the public log.');
  const pName = el('input'); pName.placeholder = 'display name';
  const pAbout = el('input', 'grow'); pAbout.placeholder = 'about (optional)';
  const pGo = el('button', 'btn', 'PUBLISH PROFILE');
  const pSt = el('span', 'meta', '');
  const pRow = el('div', 'row'); pRow.append(pName, pAbout, pGo, pSt);
  profSec.append(pRow);
  c.append(profSec);
  pGo.onclick = async () => {
    pSt.textContent = 'publishing…';
    const r = await j(api('/buzz/profile'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ relay: rv(), name: pName.value.trim(), about: pAbout.value.trim() || null }),
    });
    pSt.textContent = r.ok ? 'published ✓' : 'failed: ' + r.error;
  };

  const chanSec = section('Channels', 'Click a channel to read it; use the box to post as this agent.');
  const chList = el('div');
  const chSt = el('span', 'meta', '');
  const chGo = el('button', 'btn', 'LIST CHANNELS');
  const chRow = el('div', 'row'); chRow.append(chGo, chSt);
  const joinIn = el('input', 'grow'); joinIn.placeholder = 'channel id to join (NIP-29 join request)';
  const joinGo = el('button', 'btn', 'REQUEST JOIN');
  const joinRow = el('div', 'row'); joinRow.append(joinIn, joinGo);
  const msgs = el('div');
  const postIn = el('input', 'grow'); postIn.placeholder = 'message…';
  const postGo = el('button', 'btn solid', 'POST');
  const postRow = el('div', 'row'); postRow.append(postIn, postGo);
  postRow.style.display = 'none';
  let curChan = null;
  chanSec.append(chRow, chList, joinRow, msgs, postRow);
  c.append(chanSec);

  const readChan = async (id, name) => {
    curChan = id;
    msgs.replaceChildren(el('div', 'meta', 'reading #' + (name || id) + '…'));
    const r = await j(api('/buzz/read') + `?relay=${encodeURIComponent(rv())}&channel=${encodeURIComponent(id)}&limit=30`);
    msgs.replaceChildren();
    postRow.style.display = 'flex';
    if (!r.ok) { msgs.append(el('div', 'ev err', r.error)); return; }
    const keyRow = await j('/api/key?key=' + encodeURIComponent(sel));
    for (const msg of (r.messages || [])) {
      const line = el('div', 'msg' + (keyRow.ok && msg.author === keyRow.hex ? ' mine' : ''));
      line.append(el('span', 'who', msg.author.slice(0, 8) + '… '), document.createTextNode(msg.content));
      line.append(el('div', 'meta', new Date(msg.at * 1000).toLocaleString()));
      msgs.append(line);
    }
  };
  chGo.onclick = async () => {
    chSt.textContent = 'authenticating + listing…';
    const r = await j(api('/buzz/channels') + '?relay=' + encodeURIComponent(rv()));
    chSt.textContent = r.ok ? (r.channels.length + ' channels') : 'failed: ' + r.error;
    chList.replaceChildren();
    for (const ch of (r.channels || [])) {
      const n = el('div', 'chan', '#' + (ch.name || '(unnamed)') + ' · ' + ch.id);
      n.onclick = () => readChan(ch.id, ch.name);
      chList.append(n);
    }
  };
  joinGo.onclick = async () => {
    chSt.textContent = 'requesting…';
    const r = await j(api('/buzz/join'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ relay: rv(), channel: joinIn.value.trim() }),
    });
    chSt.textContent = r.ok ? r.note : 'failed: ' + r.error;
  };
  postGo.onclick = async () => {
    if (!curChan || !postIn.value.trim()) return;
    const r = await j(api('/buzz/post'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ relay: rv(), channel: curChan, message: postIn.value }),
    });
    if (r.ok) { postIn.value = ''; readChan(curChan); }
    else msgs.append(el('div', 'ev err', 'post failed: ' + r.error));
  };

  const lisSec = section('Mention listener',
    'Supervised presence: declare presence.buzz in the manifest (or Overview → Declare presence), re-ratify, and ACTIVATE the agent — the supervisor runs this channel alongside any others (telegram, slack, plugins) under one lease. Live status and manual per-channel stop live in Overview → Presence channels.');
  const supNote = el('div', 'kv');
  lisSec.append(supNote);
  const lLines = el('pre'); lLines.style.display = 'none';
  lisSec.append(lLines);
  c.append(lisSec);
  const pollListener = async () => {
    const r = await j(api('/listener'));
    if (!r.ok) return;
    const ch = (r.channels || {}).buzz;
    supNote.replaceChildren(el('span', 'k', 'buzz channel'), el('span', 'v',
      !((r.declared || []).includes('buzz')) ? 'not declared — nothing to supervise'
        : ch && ch.running ? 'running'
        : (ch && ch.note) || 'not running (activate the agent; supervisor starts it)'));
    if (ch && (ch.lines || []).length) { lLines.style.display = 'block'; lLines.textContent = ch.lines.join('\n'); }
  };
  pollListener();
  listenerPoll = setInterval(pollListener, 3000);
}

// ------------------------------------------------------------ connectors

async function renderConnectors(c) {
  c.append(help('Two layers. The HOST LIBRARY holds named connector configurations (kind + caps, no secrets) — configure once, assign to any agent. A GRANT copies one into this agent’s manifest, sealing any credential to this agent’s key alone. Grants are constitutional: each one changes the manifest hash and needs re-ratification, and each travels with the agent — portability includes capabilities and their sealed credentials. A destination host only needs to bind the kind; a declared kind it cannot bind fails loudly at run start.'));
  const libHint = el('div', 'row');
  const libBtn = el('button', 'btn', 'OPEN HOST CONNECTOR LIBRARY');
  libBtn.onclick = () => { hostView = true; render(); };
  libHint.append(libBtn, el('span', 'meta', 'definitions are host-scoped, shared by all agents — this tab only grants and revokes for the selected agent'));
  c.append(libHint);
  c.append(help('The mcp kind speaks the Model Context Protocol (2026-07-28, with automatic fallback to initialize-era servers). stdio example caps: {"transport":"stdio","command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/data"],"allowed_tools":["read_text_file","list_directory"]}. Remote example: {"transport":"http","url":"https://mcp.example.com/mcp","allowed_tools":["search"],"oauth_client_id":"…"} — grant via OAuth below, or paste a bearer token as the secret. allowed_tools is required: the server offers whatever it likes, the manifest decides what the agent may touch.'));

  const lib = await j('/api/connectors');
  if (!lib.ok) { c.append(el('div', 'ev err', 'error: ' + lib.error)); return; }
  const d = await j(api('/manifest'));
  if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }

  // ---- this agent's grants
  const gSec = section('This agent’s grants',
    'What the manifest declares now. Revoking is an amendment too — until re-ratified the agent cannot run at all.');
  const grants = (d.manifest.connectors || []);
  if (!grants.length) gSec.append(kv('grants', 'none — the agent can think and speak, not act'));
  for (const g of grants) {
    const row = el('div', 'row');
    row.append(el('span', 'v', `${g.type} · caps ${JSON.stringify(g.caps || {})} · credential ${g.credential ? 'sealed to this agent' : 'none'}`));
    const rv = el('button', 'btn danger', 'REVOKE');
    row.append(rv);
    gSec.append(row);
    rv.onclick = async () => {
      const r = await j(api('/connectors/' + encodeURIComponent(g.type)), { method: 'DELETE' });
      gStatus.textContent = r.ok ? `revoked ${g.type} — re-ratify in the Manifest tab` : 'failed: ' + r.error;
      loadRoster(); render();
    };
  }
  const gRow = el('div', 'row');
  const gSel = el('select');
  for (const e of (lib.library || [])) {
    const o = el('option', null, `${e.name} (${e.kind})`);
    o.value = e.name; gSel.append(o);
  }
  if (!(lib.library || []).length) gSel.append(el('option', null, 'library is empty — add below'));
  const gCred = el('input', 'grow'); gCred.type = 'password';
  gCred.placeholder = 'secret to seal to this agent (optional)';
  const gGo = el('button', 'btn solid', 'GRANT');
  const gStatus = el('span', 'meta', '');
  gRow.append(gSel, gCred, gGo, gStatus);
  gSec.append(gRow,
    help('The secret (if any) is sealed with NIP-44 to this agent’s key at grant time and lands in the manifest as a blob — never stored anywhere else, unreadable by other agents or hosts.'));
  c.append(gSec);
  gGo.onclick = async () => {
    if (!gSel.value) return;
    const entry = (lib.library || []).find(e => e.name === gSel.value);
    const wantsOauth = entry && entry.caps && entry.caps.oauth_client_id && !gCred.value;
    if (wantsOauth) {
      gStatus.textContent = 'starting OAuth…';
      const r = await j(api('/connectors/oauth'), {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: gSel.value }),
      });
      if (!r.ok) { gStatus.textContent = 'failed: ' + r.error; return; }
      gStatus.replaceChildren();
      const a = el('a', null, 'AUTHORIZE IN BROWSER →');
      a.href = r.auth_url; a.target = '_blank'; a.style.color = 'var(--amber)';
      gStatus.append(a, el('span', 'meta', ' waiting for the callback…'));
      const before = grants.length;
      const poll = setInterval(async () => {
        const d2 = await j(api('/manifest'));
        if (d2.ok && (d2.manifest.connectors || []).length > before) {
          clearInterval(poll);
          gStatus.textContent = 'granted via OAuth — re-ratify in the Manifest tab';
          loadRoster(); render();
        }
      }, 3000);
      return;
    }
    gStatus.textContent = 'granting…';
    const r = await j(api('/connectors'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: gSel.value, credential: gCred.value || null }),
    });
    gStatus.textContent = r.ok ? `granted ${r.kind} — re-ratify in the Manifest tab` : 'failed: ' + r.error;
    gCred.value = '';
    loadRoster(); if (r.ok) render();
  };


}

// ------------------------------------------------------------ host library (host-scoped, all agents)

async function renderLibrary(c) {
  c.append(help('HOST-SCOPED: this library belongs to the host, not to any one agent. Entries are named connector configurations (kind + caps — never secrets) stored in connectors.yaml under the state directory. Grant them to individual agents from an agent’s Connectors tab; each grant is a ratified manifest amendment for that agent alone.'));
  const lib = await j('/api/connectors');
  if (!lib.ok) { c.append(el('div', 'ev err', 'error: ' + lib.error)); return; }

  // Which agents hold a grant of each kind — the all-agents view.
  const grantsByKind = {};
  for (const a of agents) {
    const d = await j(`/api/agents/${encodeURIComponent(a.npub)}/manifest`);
    if (!d.ok) continue;
    for (const g of (d.manifest.connectors || [])) {
      (grantsByKind[g.type] = grantsByKind[g.type] || []).push(a.name || a.npub.slice(0, 12));
    }
  }

  const lSec = section('Entries',
    'Kinds this host can bind: ' + (lib.host_binds || []).join(', ') + '. An entry granted to an agent travels in that agent’s manifest — a destination host only needs to bind the kind.');
  const entries = (lib.library || []).slice();
  const list = el('div');
  const lStatus = el('span', 'meta', '');
  const drawList = () => {
    list.replaceChildren();
    if (!entries.length) list.append(kv('library', 'empty'));
    entries.forEach((e, i) => {
      const row = el('div', 'row');
      const holders = grantsByKind[e.kind] || [];
      row.append(el('span', 'v', `${e.name} · ${e.kind} · caps ${JSON.stringify(e.caps || {})}`));
      row.append(el('span', 'meta', holders.length ? 'granted to: ' + holders.join(', ') : 'granted to: nobody'));
      const del = el('button', 'btn danger', 'REMOVE');
      row.append(del);
      del.onclick = async () => {
        entries.splice(i, 1);
        await saveLib();
      };
      list.append(row);
    });
  };
  const nName = el('input'); nName.placeholder = 'name (e.g. publish-main)';
  const nKind = el('select');
  for (const k of (lib.host_binds || [])) { const o = el('option', null, k); o.value = k; nKind.append(o); }
  const nCaps = el('input', 'grow'); nCaps.placeholder = 'caps JSON (e.g. {"relays":["wss://nos.lol"]})';
  const nGo = el('button', 'btn', 'ADD TO LIBRARY');
  const nRow = el('div', 'row'); nRow.append(nName, nKind, nCaps, nGo, lStatus);
  lSec.append(list, nRow,
    help('caps are the human-owned behavioral limits enforced host-side at every call — e.g. nostr-publish requires caps.relays (a publish allowlist); mcp requires caps.allowed_tools (the server offers whatever it likes, the manifest decides). Removing an entry here does NOT revoke existing grants — those live in agent manifests and are revoked per-agent.'));
  lSec.append(help('mcp stdio example caps: {"transport":"stdio","command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/data"],"allowed_tools":["read_text_file","list_directory"]} — remote: {"transport":"http","url":"https://mcp.example.com/mcp","allowed_tools":["search"],"oauth_client_id":"…"}.'));
  c.append(lSec);
  const saveLib = async () => {
    const r = await j('/api/connectors', {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ library: entries }),
    });
    lStatus.textContent = r.ok ? `saved (${r.count} entries)` : 'rejected: ' + r.error;
    if (r.ok) render();
  };
  drawList();
  nGo.onclick = async () => {
    let caps = {};
    if (nCaps.value.trim()) {
      try { caps = JSON.parse(nCaps.value); } catch { lStatus.textContent = 'caps is not valid JSON'; return; }
    }
    if (!nName.value.trim()) { lStatus.textContent = 'name required'; return; }
    entries.push({ name: nName.value.trim(), kind: nKind.value, caps });
    await saveLib();
  };
}

// ------------------------------------------------------------ credentials

function renderCreds(c) {
  c.append(help('Credential custody: secrets are sealed with NIP-44 to the agent’s own key, so the manifest can carry connector credentials without carrying plaintext. The plaintext exists only transiently, per-credential, at the instant of use — exposure at the instant of use is a pre-existing property of any credential, not new risk.'));

  const sealSec = section('Seal a secret', 'Paste a secret (API key, token); get back a NIP-44 blob to put in a manifest connector’s credential field. The blob is useless to anyone but this agent.');
  const sIn = el('textarea'); sIn.rows = 3; sIn.placeholder = 'plaintext secret…';
  const sGo = el('button', 'btn', 'SEAL');
  const sSt = el('span', 'meta', '');
  const sRow = el('div', 'row'); sRow.append(sGo, sSt);
  const sOut = el('pre'); sOut.style.display = 'none'; sOut.style.userSelect = 'all';
  sealSec.append(sIn, sRow, sOut);
  c.append(sealSec);
  sGo.onclick = async () => {
    sSt.textContent = 'sealing…';
    const r = await j(api('/credential/seal'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ plaintext: sIn.value }),
    });
    if (r.ok) { sIn.value = ''; sSt.textContent = 'sealed ✓ (plaintext cleared)'; sOut.style.display = 'block'; sOut.textContent = r.nip44; }
    else sSt.textContent = 'failed: ' + r.error;
  };

  const openSec = section('Open a sealed blob (debug)', 'Decrypts a blob with the agent’s key and SHOWS THE PLAINTEXT on screen. Debug tool only — prefer letting connectors decrypt at the instant of use.');
  const oIn = el('textarea'); oIn.rows = 3; oIn.placeholder = 'nip44 blob…';
  const oGo = el('button', 'btn danger', 'OPEN (REVEALS PLAINTEXT)');
  const oSt = el('span', 'meta', '');
  const oRow = el('div', 'row'); oRow.append(oGo, oSt);
  const oOut = el('pre'); oOut.style.display = 'none';
  openSec.append(oIn, oRow, oOut);
  c.append(openSec);
  oGo.onclick = async () => {
    const r = await j(api('/credential/open'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nip44: oIn.value }),
    });
    oSt.textContent = r.ok ? 'decrypted' : 'failed: ' + r.error;
    if (r.ok) { oOut.style.display = 'block'; oOut.textContent = r.plaintext; }
  };
}

// ------------------------------------------------------------ founding

document.getElementById('libtoggle').onclick = () => {
  hostView = true;
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('sel'));
  render();
};

document.getElementById('foundtoggle').onclick = () => {
  const f = document.getElementById('foundform');
  f.style.display = f.style.display === 'block' ? 'none' : 'block';
};

document.getElementById('importtoggle').onclick = () => {
  const f = document.getElementById('importform');
  f.style.display = f.style.display === 'block' ? 'none' : 'block';
};

document.getElementById('importgo').onclick = async () => {
  const st = document.getElementById('i-status');
  st.style.display = 'block';
  let bundle;
  try { bundle = JSON.parse(document.getElementById('i-bundle').value); }
  catch { st.textContent = 'not valid JSON'; return; }
  st.textContent = 'verifying and importing… (key decrypt is deliberately slow)';
  const r = await j('/api/agents/import', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ bundle, bundle_passphrase: document.getElementById('i-pass').value || null }),
  });
  st.textContent = r.ok
    ? `imported ${r.name || r.npub.slice(0, 12)} · ${r.log_entries} log entries · ${r.index_rows} index rows${r.index_dropped ? ` (${r.index_dropped} dropped: disagreed with the signed log)` : ''} · ${r.ratified ? 'ratified' : 'NOT ratified'} — arrives inactive`
    : 'refused: ' + r.error;
  if (r.ok) { document.getElementById('i-bundle').value = ''; loadRoster(); }
};

document.getElementById('foundgo').onclick = async () => {
  const st = document.getElementById('f-status');
  st.style.display = 'block';
  st.textContent = 'founding…';
  const r = await j('/api/agents/found', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      name: document.getElementById('f-name').value.trim(),
      purpose: document.getElementById('f-purpose').value.trim(),
      suspend_keys: [document.getElementById('f-suspend').value.trim()],
      draft_with: document.getElementById('f-draft').checked ? 'anthropic' : null,
    }),
  });
  if (!r.ok) { st.textContent = 'refused: ' + r.error; return; }
  st.textContent = `founded ${r.npub.slice(0, 16)}… drafted by ${r.drafted_by} — review, then ratify`;
  sel = r.npub; tab = 'manifest';
  document.querySelectorAll('nav button').forEach(x => x.classList.toggle('sel', x.dataset.tab === 'manifest'));
  await loadRoster(); render();
};

loadStatus().then(loadRoster);
setInterval(loadStatus, 15000);
