// Apiary cockpit. All dynamic strings render through textContent — agent
// names, log fields, model output, tool args, and errors are DATA, and the
// governance origin never interprets data as markup. (CSP backs this up:
// no inline script, no external sources.)
'use strict';

let sel = null, tab = 'overview', agents = [], owners = [], hostStatus = {};
let hostView = null; // null | 'library' | 'found' | 'import'
let listenerPoll = null;

// Desktop mode hands the per-launch token in the boot URL; every API call
// echoes it back in a header. Without a token this is a no-op.
const TOKEN = new URLSearchParams(location.search).get('token');
const REMOTE = new URLSearchParams(location.search).get('remote');
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

function ownerHolders(keys) {
  const byNpub = new Map();
  for (const identity of [...owners, ...agents]) byNpub.set(identity.npub, identity);
  return [...byNpub.values()].filter(identity => keys.some(k => k === identity.npub));
}

function field(labelText, control, hint) {
  const label = el('label', 'field');
  label.append(el('span', null, labelText), control);
  if (hint) label.append(el('small', null, hint));
  return label;
}

const connectorKindLabel = {
  obsidian: 'Obsidian vault',
  'markdown-vault': 'Markdown folder',
  'web-search': 'Full web search & research',
  'web-fetch': 'Web page reader',
  files: 'Files and documents',
  git: 'Git repositories',
  mcp: 'MCP server',
  'nostr-publish': 'Nostr publish',
  'mock-echo': 'Test connector',
};

function connectorSupportsReadWrite(kind, caps) {
  if (kind === 'obsidian' || kind === 'markdown-vault') return true;
  if (kind === 'mcp') return !/\/readonly(?:\/|$)/.test((caps && caps.url) || '');
  return false;
}

function connectorAccessMode(kind, caps) {
  if (kind === 'obsidian' || kind === 'markdown-vault') return caps && caps.write ? 'read-write' : 'read-only';
  if (kind === 'mcp') {
    if (caps && caps.access) return caps.access;
    return /\/readonly(?:\/|$)/.test((caps && caps.url) || '') ? 'read-only' : 'read-write';
  }
  return 'read-only';
}

function setConnectorAccess(kind, caps, mode) {
  if (kind === 'obsidian' || kind === 'markdown-vault') caps.write = mode === 'read-write';
  else if (kind === 'mcp') caps.access = mode;
}

function accessSelect(mode = 'read-only') {
  const select = el('select');
  for (const [value, label] of [['read-only', 'Read only'], ['read-write', 'Read + write']]) {
    const option = el('option', null, label); option.value = value; select.append(option);
  }
  select.value = mode;
  select.setAttribute('aria-label', 'Connector access');
  return select;
}

// ------------------------------------------------------------ host status

async function loadStatus() {
  try { hostStatus = await j('/api/status'); } catch { hostStatus = {}; }
  const set = (id, text, cls) => {
    const n = document.getElementById(id);
    n.textContent = text;
    if (cls !== undefined) n.className = cls;
  };
  set('c-ver', 'Apiary v' + (hostStatus.version || '?'));
  document.getElementById('c-home').title = 'state directory: ' + (hostStatus.home || '?');
  set('c-home', 'State · ' + ((hostStatus.home || '?').split('/').filter(Boolean).pop() || '/'));
  set('c-auth', 'Authentication · ' + (hostStatus.auth || '?')
      + (hostStatus.token_gated ? ' + token' : '')
      + (REMOTE ? ' · SSH → ' + REMOTE : ''));
  set('c-model', hostStatus.anthropic_key_present ? 'Drafting model ready' : 'Drafting model unavailable',
      'chip ' + (hostStatus.anthropic_key_present ? 'ok' : ''));
  document.getElementById('c-model').title = hostStatus.anthropic_key_present
    ? 'The host can use ANTHROPIC_API_KEY to draft new agent configurations'
    : 'No host ANTHROPIC_API_KEY. Agent-owned inference credentials may still be configured and ready.';
  set('c-lock', hostStatus.unlocked ? 'unlocked' : 'LOCKED — click to unlock',
      'chip click ' + (hostStatus.unlocked ? 'ok' : 'bad'));
  // Once unlocked, never ask again: the passphrase prompt disappears and
  // the bar only offers LOCK.
  const unlocked = !!hostStatus.unlocked;
  document.getElementById('u-pass').style.display = unlocked ? 'none' : '';
  document.getElementById('u-go').style.display = unlocked ? 'none' : '';
  document.getElementById('u-remember-row').style.display = !unlocked && hostStatus.can_remember_unlock ? '' : 'none';
  document.getElementById('u-forget').style.display = hostStatus.automatic_unlock && hostStatus.can_forget_unlock ? '' : 'none';
  document.getElementById('u-help').textContent = unlocked
    ? (hostStatus.automatic_unlock
      ? 'keystore unlocked · automatic launch unlock is protected by macOS Keychain'
      : 'keystore unlocked for this session — LOCK to forget the passphrase')
    : 'passphrase unlocks the NIP-49 keystore for this session — needed to run, ratify, found, post, seal:';
}

async function loadOwners() {
  try {
    const d = await j('/api/owners');
    owners = d.ok ? (d.owners || []) : [];
  } catch {
    owners = [];
  }
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
    body: JSON.stringify({
      passphrase: document.getElementById('u-pass').value,
      remember: !!document.getElementById('u-remember').checked,
    }),
  });
  st.textContent = r.ok
    ? ((r.verified_against_key ? 'unlocked ✓' : 'unlocked ✓ (empty keystore)')
      + (r.automatic_unlock ? ' · saved in macOS Keychain' : '')
      + (r.remember_warning ? ' · could not remember: ' + r.remember_warning : ''))
    : 'refused: ' + r.error;
  if (r.ok) {
    document.getElementById('u-pass').value = '';
    setTimeout(() => { document.getElementById('unlockbar').style.display = 'none'; }, 1200);
    await loadOwners();
  }
  await loadStatus(); render();
};
document.getElementById('u-lock').onclick = async () => {
  await j('/api/lock', { method: 'POST' });
  document.getElementById('u-status').textContent = hostStatus.automatic_unlock
    ? 'locked for this session · automatic unlock remains saved'
    : 'locked — passphrase forgotten';
  loadStatus();
};
document.getElementById('u-forget').onclick = async () => {
  const r = await j('/api/unlock/forget', { method: 'POST' });
  document.getElementById('u-status').textContent = r.ok
    ? 'automatic unlock removed from macOS Keychain'
    : 'could not remove automatic unlock: ' + r.error;
  await loadStatus();
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
  if (!agents.length) root.append(el('div', 'empty', 'Your first agent will appear here.'));
  const running = new Set((hostStatus.listeners || []).filter(l => l.running).map(l => l.npub));
  for (const a of agents) {
    const card = el('button', 'agent' + (sel === a.npub ? ' sel' : ''));
    card.type = 'button';
    card.setAttribute('aria-pressed', sel === a.npub ? 'true' : 'false');
    const nm = el('div', 'nm', a.name || '(unnamed)');
    nm.append(el('span', 'badge ' + (a.ratified ? 'rat' : 'unrat'), a.ratified ? 'ratified' : 'unratified'));
    nm.append(el('span', 'badge ' + (a.active ? 'live' : 'unrat'), a.active ? 'active' : 'inactive'));
    if (running.has(a.npub)) nm.append(el('span', 'badge live', 'listening'));
    card.append(nm, el('div', 'np', a.npub), el('div', 'np', a.log_entries + ' signed events'));
    card.onclick = () => { hostView = null; sel = a.npub; render(); loadRoster(); };
    root.append(card);
  }
}

document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  hostView = null;
  tab = b.dataset.tab;
  document.querySelectorAll('nav button').forEach(x => x.classList.toggle('sel', x === b));
  document.querySelectorAll('nav button').forEach(x => x.setAttribute('aria-current', x === b ? 'page' : 'false'));
  render();
});

function openTab(next) {
  hostView = null; tab = next;
  document.querySelectorAll('nav button').forEach(x => {
    const current = x.dataset.tab === next;
    x.classList.toggle('sel', current);
    x.setAttribute('aria-current', current ? 'page' : 'false');
  });
  render();
}

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
  if (hostView === 'library') return renderLibrary(c);
  if (hostView === 'found') return renderFound(c);
  if (hostView === 'import') return renderImport(c);
  if (!sel && !agents.length) return renderWelcome(c);
  if (!sel) { c.append(el('div', 'empty', 'Choose an agent from the sidebar.')); return; }
  await ratifyBanner(c);
  if (tab === 'overview') return renderOverview(c);
  if (tab === 'run') return renderRun(c);
  if (tab === 'log') return renderLog(c);
  if (tab === 'inference') return renderInference(c);
  if (tab === 'manifest') return renderManifest(c);
  if (tab === 'buzz') return renderBuzz(c);
  if (tab === 'connectors') return renderConnectors(c);
  if (tab === 'routines') return renderRoutines(c);
  if (tab === 'creds') return renderCreds(c);
}

// ------------------------------------------------------------ first run

function setupProgress(current) {
  const steps = el('div', 'setup-steps');
  for (let i = 1; i <= 3; i++) steps.append(el('span', 'setup-step' + (i < current ? ' done' : i === current ? ' current' : '')));
  return steps;
}

function renderWelcome(c) {
  const wrap = el('section', 'setup');
  const card = el('div', 'setup-card');
  wrap.append(card); c.append(wrap);
  const eyebrow = el('div', 'eyebrow', 'Set up Apiary');
  const status = el('div', 'meta');
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');

  if (!hostStatus.unlocked) {
    card.append(eyebrow, el('h2', null, 'Protect your agent workspace'),
      help('Create the passphrase that encrypts identities and credentials on this device. Apiary keeps it in memory only while unlocked.'),
      setupProgress(1));
    const pass = el('input'); pass.type = 'password'; pass.autocomplete = 'new-password';
    const confirm = el('input'); confirm.type = 'password'; confirm.autocomplete = 'new-password';
    const go = el('button', 'btn solid', 'Continue');
    card.append(field('Workspace passphrase', pass, 'Use at least 10 characters and store it somewhere safe.'),
      field('Confirm passphrase', confirm), el('div', 'row'), status);
    card.querySelector('.row').append(go);
    go.onclick = async () => {
      if (pass.value.length < 10) { status.textContent = 'Use at least 10 characters.'; pass.focus(); return; }
      if (pass.value !== confirm.value) { status.textContent = 'The passphrases do not match.'; confirm.focus(); return; }
      go.disabled = true; status.textContent = 'Creating your encrypted workspace…';
      const r = await j('/api/unlock', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({passphrase:pass.value}) });
      pass.value = ''; confirm.value = ''; go.disabled = false;
      if (!r.ok) { status.textContent = 'Could not unlock: ' + r.error; return; }
      await Promise.all([loadStatus(), loadOwners()]); render();
    };
    return;
  }

  if (!owners.length) {
    card.append(eyebrow, el('h2', null, 'Create your approval identity'),
      help('This is your human authority in Apiary. It approves agent configurations and can stop an agent. It is separate from every agent identity.'),
      setupProgress(2));
    const name = el('input'); name.placeholder = 'e.g. Ryan'; name.autocomplete = 'name';
    const go = el('button', 'btn solid', 'Create approval identity');
    const note = el('div', 'attention');
    note.append(el('b', null, 'Why this is separate'), help('An agent can never approve its own permissions. Your approval key is encrypted with the workspace passphrase and never appears as a runnable agent.'));
    const row = el('div', 'row'); row.append(go);
    card.append(field('Your name', name, 'Used only as a local label.'), note, row, status);
    go.onclick = async () => {
      if (!name.value.trim()) { status.textContent = 'Enter a name for your approval identity.'; name.focus(); return; }
      go.disabled = true; status.textContent = 'Creating and encrypting your approval identity…';
      const r = await j('/api/owners', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({name:name.value.trim()}) });
      go.disabled = false;
      if (!r.ok) { status.textContent = 'Could not create the identity: ' + r.error; return; }
      await Promise.all([loadOwners(), loadStatus()]); render();
    };
    return;
  }

  card.append(eyebrow, el('h2', null, 'Create your first agent'),
    help('Start with a clear job. Apiary creates a conservative configuration for you to review before the agent can run.'),
    setupProgress(3));
  const name = el('input'); name.placeholder = 'e.g. Morning brief';
  const purpose = el('textarea'); purpose.rows = 4; purpose.placeholder = 'What should this agent reliably help you do?';
  const owner = el('select');
  for (const identity of owners) { const option = el('option', null, identity.name); option.value = identity.npub; owner.append(option); }
  const draft = el('input'); draft.type = 'checkbox'; draft.checked = !!hostStatus.anthropic_key_present; draft.disabled = !hostStatus.anthropic_key_present;
  const draftLabel = el('label', 'field'); const draftLine = el('span'); draftLine.append(draft, document.createTextNode(' Tailor the configuration with the connected model'));
  draftLabel.append(draftLine, el('small', null, hostStatus.anthropic_key_present ? 'You will review everything before approval.' : 'No host model credential is configured, so Apiary will use its conservative template.'));
  const go = el('button', 'btn solid', 'Create draft');
  const row = el('div', 'row'); row.append(go);
  card.append(field('Agent name', name), field('Purpose', purpose), field('Approved by', owner), draftLabel, row, status);
  go.onclick = async () => {
    if (!name.value.trim()) { status.textContent = 'Give the agent a name.'; name.focus(); return; }
    if (!purpose.value.trim()) { status.textContent = 'Describe what the agent should do.'; purpose.focus(); return; }
    go.disabled = true; status.textContent = 'Creating the identity and draft configuration…';
    const r = await j('/api/agents/found', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({
      name:name.value.trim(), purpose:purpose.value.trim(), suspend_keys:[owner.value], draft_with:draft.checked ? 'anthropic' : null,
    }) });
    go.disabled = false;
    if (!r.ok) { status.textContent = 'Could not create the agent: ' + r.error; return; }
    sel = r.npub; tab = 'manifest'; hostView = null;
    document.querySelectorAll('nav button').forEach(x => x.classList.toggle('sel', x.dataset.tab === 'manifest'));
    await Promise.all([loadRoster(), loadStatus()]); render();
  };
}

// ------------------------------------------------------------ overview

// ------------------------------------------------------- ratify banner

/// Amendments (grants, routines, caps, proposals) leave the manifest
/// UNRATIFIED — nothing runs until a governor countersigns. Say so on
/// every tab, with the button right there.
async function ratifyBanner(c) {
  const a = agents.find(x => x.npub === sel);
  if (!a || a.ratified) return;
  const box = el('section', 'attention');
  box.append(el('h2', null, 'Review changes before this agent can run'),
    help(`${a.name || 'This agent'} is paused because its configuration has not been approved. Apiary will show you the effective setup and the exact file changes before signing.`));
  const d = await j(api('/manifest'));
  const keys = (d.ok && d.manifest && d.manifest.governance && d.manifest.governance.suspend_keys) || [];
  const holders = ownerHolders(keys);
  const row = el('div', 'row');
  const review = el('button', 'btn solid', 'Review changes');
  const st = el('span', 'meta', holders.length ? '' : 'This host does not hold an approval key named by this configuration.');
  row.append(review, st); box.append(row);
  c.append(box);

  review.onclick = () => {
    review.remove();
    if (!d.ok) { st.textContent = 'Could not load the configuration: ' + d.error; return; }
    const m = d.manifest || {};
    const inf = (m.inference || [])[0];
    const summary = el('div', 'section');
    summary.append(el('h3', null, 'Effective setup'),
      kv('Model', inf ? `${inf.provider} / ${inf.model}` : 'No model configured'),
      kv('Daily token limit', ((m.governance || {}).budgets || {}).tokens_per_day || 'No limit set'),
      kv('Capabilities', `${(m.connectors || []).length} granted`),
      kv('Always-on channels', Object.keys(m.presence || {}).length),
      kv('Automations', (m.routines || []).length));
    const technical = el('details', 'technical');
    technical.append(el('summary', null, d.approved_yaml ? 'Technical diff' : 'Full configuration for first approval'));
    technical.append(d.approved_yaml ? lineDiff(d.approved_yaml, d.yaml || '') : (() => {
      const pre = el('pre'); pre.textContent = d.yaml || ''; return pre;
    })());
    summary.append(technical); box.append(summary);

    if (!holders.length) {
      st.textContent = 'Approval is unavailable here. Add a key listed under governance.suspend_keys, or use the external approval tools in Configuration.';
      const open = el('button', 'btn', 'Open Configuration');
      open.onclick = () => openTab('manifest');
      box.append(open);
      return;
    }
    const who = el('select');
    for (const h of holders) { const o = el('option', null, h.name || h.npub.slice(0, 16)); o.value = h.npub; who.append(o); }
    const rat = el('button', 'btn solid', 'Approve configuration');
    const approveRow = el('div', 'row');
    approveRow.append(el('span', 'meta', 'Approve as'), who, rat); box.append(approveRow);
    rat.onclick = async () => {
      rat.disabled = true; st.textContent = 'Signing with the agent and your approval identity…';
      const r = await j(api('/ratify'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ as: who.value }) });
      st.textContent = r.ok
        ? (r.snapshot_warning ? 'Approved, but Apiary could not save the review snapshot: ' + r.snapshot_warning : 'Approved. The configuration is now in force.')
        : 'Could not approve: ' + r.error;
      rat.disabled = false;
      if (r.ok) { await loadRoster(); render(); }
    };
  };
}

// ------------------------------------------------------ proposal banner

function lineDiff(a, b) {
  const A = a.split('\n'), B = b.split('\n');
  const setA = new Set(A), setB = new Set(B);
  const out = el('pre', 'diff');
  out.style.cssText = 'white-space:pre-wrap;font-size:11px;max-height:280px;overflow:auto;margin:6px 0;';
  // Simple: lines only in B are additions, only in A are removals; common lines shown dim.
  const seenB = new Set();
  for (const line of B) {
    const d = el('div', null, (setA.has(line) ? '  ' : '+ ') + line);
    if (!setA.has(line)) d.style.color = '#7ec87e';
    else d.style.opacity = '0.45';
    out.append(d);
    seenB.add(line);
  }
  for (const line of A) if (!setB.has(line)) { const d = el('div', null, '- ' + line); d.style.color = '#e07070'; out.append(d); }
  return out;
}

async function proposalBanner(c) {
  const p = await j(api('/proposal'));
  if (!p.ok || !p.pending) return;
  const box = el('div', 'ev');
  box.style.borderColor = 'var(--amber)';
  const who = (agents.find(a => a.npub === sel) || {}).name || 'the agent';
  box.append(el('b', null, `${who} proposes an amendment — waiting for you`));
  box.append(kv('summary', p.summary));
  if (p.reason) box.append(kv('its reason', p.reason));
  box.append(kv('proposed', p.at ? new Date(p.at).toLocaleString() : '—'));
  const details = el('details');
  details.append(el('summary', null, 'what would change'));
  details.append(lineDiff(p.current_yaml || '', p.proposed_yaml || ''));
  box.append(details);
  const row = el('div', 'row');
  const acc = el('button', 'btn solid', 'Accept draft');
  const rej = el('button', 'btn danger', 'Reject');
  const st = el('span', 'meta', '');
  row.append(acc, rej, st);
  box.append(row, help('Accepting moves the draft into the configuration review above. It does not approve or run the changes. The agent can propose; only you can enact.'));
  c.append(box);
  acc.onclick = async () => {
    const r = await j(api('/proposal/accept'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    st.textContent = r.ok ? 'Accepted. Review and approve the configuration above.' : 'Failed: ' + r.error;
    if (r.ok) { loadRoster(); setTimeout(render, 800); }
  };
  rej.onclick = async () => {
    const r = await j(api('/proposal/reject'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    st.textContent = r.ok ? 'rejected' : 'failed: ' + r.error;
    if (r.ok) setTimeout(render, 500);
  };
}

function metric(label, value) {
  const node = el('div', 'metric');
  node.append(el('span', 'label', label), el('span', 'value', value));
  return node;
}

function quick(title, description, target) {
  const button = el('button', 'quick'); button.type = 'button';
  button.append(el('b', null, title), el('span', null, description));
  button.onclick = () => openTab(target);
  return button;
}

async function renderOverview(c) {
  await proposalBanner(c);
  const [d, spend, listener] = await Promise.all([j(api('/manifest')), j(api('/spend')), j(api('/listener'))]);
  if (!d.ok) { c.append(el('div', 'ev err', 'Could not load this agent: ' + d.error)); return; }
  const m = d.manifest || {};
  const roster = agents.find(a => a.npub === sel) || {};
  const models = m.inference || [];
  const taskModels = models.filter(x => inferenceRoleForName(x.name) === 'language');
  const supportingModels = models.filter(x => inferenceRoleForName(x.name) !== 'language');
  const connectors = m.connectors || [];
  const declared = listener.ok ? (listener.declared || []) : [];
  const routines = m.routines || [];

  const head = el('div', 'page-head');
  head.append(el('div', 'eyebrow', roster.active ? 'Active on this host' : 'Agent overview'),
    el('h2', 'page-title', roster.name || 'Unnamed agent'),
    el('p', 'page-lede', d.ratified
      ? 'Ready for governed tasks. Review its limits, connections, and always-on presence at a glance.'
      : 'Its draft configuration is waiting for your review and approval.'));
  c.append(head);

  const stats = el('div', 'metrics');
  const remaining = spend.ok && spend.remaining !== null && spend.remaining !== undefined
    ? Number(spend.remaining).toLocaleString() : 'Not limited';
  stats.append(metric('Approval', d.ratified ? 'Approved' : 'Needs review'),
    metric('Daily tokens left', remaining),
    metric('Capabilities', String(connectors.length)),
    metric('Always-on channels', String(declared.length)));
  c.append(stats);

  const shortcuts = el('div', 'quick-grid');
  shortcuts.append(quick('Start a task', 'Give this agent a one-time job.', 'run'),
    quick('Manage capabilities', 'Choose what it can read or change.', 'connectors'),
    quick('Manage inference', 'Models, memory, speech, and routing.', 'inference'));
  c.append(shortcuts);

  const active = section('Always-on presence', declared.length
    ? 'Activation keeps declared channels available on this host. One-time tasks work while inactive.'
    : 'No always-on channel is configured. One-time tasks are still available.');
  const channelBox = el('div');
  const drawChannels = l => {
    channelBox.replaceChildren();
    const kinds = l.ok ? (l.declared || []) : [];
    const supervisorNote = l.supervisor_note === 'manifest is not ratified — nothing runs'
      ? 'Waiting for approval'
      : l.supervisor_note;
    if (!kinds.length) channelBox.append(el('div', 'none', 'No channels declared'));
    for (const kind of kinds) {
      const ch = (l.channels || {})[kind] || {};
      const status = ch.running
        ? 'Running'
        : (ch.note || supervisorNote || (roster.active ? 'Starting' : 'Inactive'));
      channelBox.append(kv(kind, status));
    }
  };
  drawChannels(listener);
  const actRow = el('div', 'row');
  const actBtn = el('button', 'btn' + (roster.active ? ' danger' : ' solid'), roster.active ? 'Deactivate' : 'Activate');
  const actSt = el('span', 'meta', '');
  actRow.append(actBtn, actSt);
  active.append(channelBox, actRow);
  actBtn.onclick = async () => {
    actBtn.disabled = true;
    const r = await j(api('/active'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ active: !roster.active }) });
    actSt.textContent = r.ok ? r.note : 'Could not change activation: ' + r.error;
    await loadRoster(); render();
  };

  const setup = el('details', 'technical');
  setup.append(el('summary', null, 'Add or inspect channels'));
  const dKind = el('select');
  for (const kind of ['telegram', 'slack', 'buzz']) { const option = el('option', null, kind); option.value = kind; dKind.append(option); }
  const dCred = el('input'); dCred.type = 'password'; dCred.placeholder = 'Channel secret, if required';
  const dConf = el('textarea'); dConf.rows = 3; dConf.placeholder = 'Advanced channel settings as JSON';
  const dGo = el('button', 'btn', 'Add channel');
  const dSt = el('span', 'meta', '');
  const dRow = el('div', 'row'); dRow.append(dGo, dSt);
  setup.append(field('Channel type', dKind), field('Secret', dCred), field('Settings', dConf), dRow,
    help('Telegram and Slack require platform credentials. Buzz can be configured more easily from Workspace. Adding a channel creates a change for you to review.'));
  dGo.onclick = async () => {
    let config = {};
    try { if (dConf.value.trim()) config = JSON.parse(dConf.value); }
    catch { dSt.textContent = 'Settings must be valid JSON.'; dConf.focus(); return; }
    dGo.disabled = true; dSt.textContent = 'Encrypting and adding…';
    const r = await j(api('/presence'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: dKind.value, credential: dCred.value || null, config }) });
    dGo.disabled = false; dCred.value = '';
    dSt.textContent = r.ok ? 'Added. Review and approve the change above.' : 'Could not add channel: ' + r.error;
    if (r.ok) { await loadRoster(); render(); }
  };
  active.append(setup); c.append(active);
  listenerPoll = setInterval(async () => drawChannels(await j(api('/listener'))), 4000);

  const current = section('Current setup');
  current.append(kv('Task models', taskModels.length ? taskModels.map(x => `${x.name}: ${x.provider} / ${x.model}`).join(', ') : 'None configured'),
    kv('Default route', (m.routing || {}).default || 'Not set'),
    kv('Memory & voice', supportingModels.length ? supportingModels.map(x => `${inferenceRoleLabel[inferenceRoleForName(x.name)]}: ${x.provider}${x.model ? ' / ' + x.model : ''}`).join(', ') : 'None configured'),
    kv('Capabilities', connectors.length ? connectors.map(x => x.name || x.type).join(', ') : 'None granted'),
    kv('Automations', routines.length ? `${routines.length} configured` : 'None'),
    kv('Memory', `${(m.memory || {}).log || 'local'} log · ${(m.memory || {}).index || 'no index'}`));
  if (spend.ok && spend.budget_tokens_per_day) {
    const bar = el('div', 'bar'); const fill = el('div');
    const used = spend.used + spend.reserved;
    fill.style.width = (Math.min(1, used / spend.budget_tokens_per_day) * 100).toFixed(1) + '%';
    if (used / spend.budget_tokens_per_day > .85) fill.className = 'hot';
    bar.append(fill); current.append(bar, help(`${Number(used).toLocaleString()} of ${Number(spend.budget_tokens_per_day).toLocaleString()} daily tokens used or reserved.`));
  }
  c.append(current);

  const advanced = el('details', 'section technical');
  advanced.append(el('summary', null, 'Identity, portability, and host coordination'));
  const body = el('div');
  body.append(kv('Public identity', sel), kv('Configuration hash', d.manifest_sha256));
  const rnIn = el('input'); rnIn.value = roster.name || '';
  const rnGo = el('button', 'btn', 'Rename'); const rnSt = el('span', 'meta', '');
  const rnRow = el('div', 'row'); rnRow.append(rnGo, rnSt);
  body.append(field('Local display name', rnIn), rnRow);
  rnGo.onclick = async () => {
    const r = await j(api('/name'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: rnIn.value.trim() }) });
    rnSt.textContent = r.ok ? 'Renamed.' : 'Could not rename: ' + r.error;
    if (r.ok) await loadRoster();
  };
  const exPass = el('input'); exPass.type = 'password'; exPass.placeholder = 'Optional handoff passphrase';
  const exTo = el('input'); exTo.placeholder = 'Or recipient npub';
  const exBtn = el('button', 'btn', 'Export agent'); const exSt = el('span', 'meta', '');
  const exRow = el('div', 'row'); exRow.append(exBtn, exSt);
  body.append(field('Protect export with', exPass), field('Seal export to', exTo), exRow,
    help('Leave both blank for your own hosts. Choose either a handoff passphrase or a recipient identity, never both.'));
  exBtn.onclick = async () => {
    if (exPass.value && exTo.value) { exSt.textContent = 'Choose a passphrase or recipient, not both.'; return; }
    exBtn.disabled = true; exSt.textContent = 'Creating verified bundle…';
    const r = await j(api('/export'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ export_passphrase: exPass.value || null, to_npub: exTo.value.trim() || null }) });
    exBtn.disabled = false; exPass.value = ''; exTo.value = '';
    exSt.textContent = r.ok ? `Saved to ${r.path}` : 'Could not export: ' + r.error;
  };
  const leaseLine = kv('Host lease', 'Checking…'); body.append(leaseLine);
  j(api('/lease')).then(lz => {
    let value = lz.ok ? (lz.note || 'No live lease') : 'Unavailable: ' + lz.error;
    if (lz.ok && lz.lease) value = lz.lease.ours ? 'Held by this host' : (lz.lease.expired ? 'Previous lease expired' : `Held by another host: ${lz.lease.holder}`);
    leaseLine.replaceChildren(el('span', 'k', 'Host lease'), el('span', 'v', value));
    if (lz.ok && lz.lease && !lz.lease.ours && !lz.lease.expired) {
      const take = el('button', 'btn danger', 'Take over on this host');
      take.onclick = async () => {
        take.disabled = true;
        const r = await j(api('/lease/takeover'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
        take.textContent = r.ok ? 'Takeover requested' : 'Takeover failed';
      };
      body.append(take);
    }
  });
  advanced.append(body); c.append(advanced);
}

// ------------------------------------------------------ inference setup

const inferenceRoleLabel = {
  language: 'Task model', embedding: 'Memory embeddings',
  transcription: 'Speech to text', speech: 'Text to speech',
};

function inferenceRoleForName(name) {
  return ({ embed: 'embedding', transcribe: 'transcription', speak: 'speech' })[name] || 'language';
}

const inferenceProviders = {
  language: [['claude-code', 'Claude Code (subscription)'], ['anthropic', 'Anthropic API'], ['openai', 'OpenAI compatible'], ['xai', 'xAI'], ['ollama', 'Ollama (local)']],
  embedding: [['ollama', 'Ollama (local)'], ['hash', 'Built-in lexical index']],
  transcription: [['apple-speech', 'Apple Speech (local)'], ['whisper-cpp', 'whisper.cpp (local)'], ['openai', 'OpenAI compatible']],
  speech: [['openai', 'OpenAI compatible / Kokoro'], ['apple-speech', 'Apple Speech (local)'], ['macos-say', 'macOS voices']],
};

// Curated, understandable defaults—not an availability claim. Every remote
// provider still offers Custom because account access and compatible servers
// vary; local engines especially may use any installed model identifier.
const inferenceModels = {
  language: {
    'claude-code': [
      ['claude-sonnet-5', 'Claude Sonnet 5 · balanced (recommended)'],
      ['claude-opus-5', 'Claude Opus 5 · complex work'],
      ['claude-haiku-4-5-20251001', 'Claude Haiku 4.5 · fastest'],
      ['claude-fable-5', 'Claude Fable 5 · highest capability'],
    ],
    anthropic: [
      ['claude-sonnet-5', 'Claude Sonnet 5 · balanced (recommended)'],
      ['claude-opus-5', 'Claude Opus 5 · complex work'],
      ['claude-haiku-4-5-20251001', 'Claude Haiku 4.5 · fastest'],
      ['claude-fable-5', 'Claude Fable 5 · highest capability / cost'],
    ],
    openai: [['gpt-5.6', 'GPT-5.6'], ['gpt-5.1', 'GPT-5.1'], ['gpt-5-mini', 'GPT-5 mini'], ['gpt-5-nano', 'GPT-5 nano']],
    xai: [['grok-4.5', 'Grok 4.5'], ['grok-4.3', 'Grok 4.3'], ['grok-build-0.1', 'Grok Build 0.1']],
    ollama: [['llama3.3', 'Llama 3.3'], ['qwen3', 'Qwen 3'], ['gemma3', 'Gemma 3']],
  },
  embedding: { ollama: [['nomic-embed-text', 'nomic-embed-text'], ['mxbai-embed-large', 'mxbai-embed-large'], ['all-minilm', 'all-minilm']] },
  transcription: {
    'whisper-cpp': [['base.en', 'Whisper base.en'], ['small.en', 'Whisper small.en'], ['medium.en', 'Whisper medium.en']],
    openai: [['gpt-4o-transcribe', 'GPT-4o Transcribe'], ['gpt-4o-mini-transcribe', 'GPT-4o mini Transcribe'], ['whisper-1', 'Whisper 1']],
  },
  speech: { openai: [['gpt-4o-mini-tts', 'GPT-4o mini TTS'], ['tts-1', 'TTS-1'], ['tts-1-hd', 'TTS-1 HD']] },
};

function inferenceDefaultBaseURL(role, provider) {
  if (provider === 'anthropic') return 'https://api.anthropic.com';
  if (provider === 'xai') return 'https://api.x.ai/v1';
  if (provider === 'openai') return 'https://api.openai.com/v1';
  if (provider === 'ollama') return 'http://localhost:11434';
  return '';
}

function inferenceProviderLabel(provider) {
  for (const choices of Object.values(inferenceProviders)) {
    const found = choices.find(([value]) => value === provider);
    if (found) return found[1];
  }
  return provider;
}

function inferenceEndpoint(slot) {
  const configured = ((slot.requires || {}).base_url || '').replace(/\/$/, '');
  if (configured) return configured;
  if (slot.provider === 'claude-code') return 'local Claude Code runtime';
  if (slot.provider === 'anthropic') return 'api.anthropic.com';
  if (slot.provider === 'xai') return 'api.x.ai';
  if (slot.provider === 'openai') return 'api.openai.com';
  if (slot.provider === 'ollama') return 'localhost:11434';
  return 'on this device';
}

function inferenceForm(slot, afterSave) {
  const form = el('div', 'connection-form');
  const role = el('select');
  for (const value of ['language', 'embedding', 'transcription', 'speech']) {
    const option = el('option', null, inferenceRoleLabel[value]); option.value = value; role.append(option);
  }
  role.value = slot ? slot.role : 'language';
  if (slot) role.disabled = true;

  const name = el('input'); name.value = slot ? slot.name : '';
  name.placeholder = 'e.g. workhorse or fast';
  const provider = el('select');
  const legacyClaude = !!(slot && slot.provider === 'anthropic' && (slot.requires || {}).auth === 'oauth');
  const initialProvider = legacyClaude ? 'claude-code' : (slot && slot.provider);
  const model = el('select');
  const customModel = el('input'); customModel.placeholder = 'Custom model identifier'; customModel.style.display = 'none';
  const modelControls = el('div'); modelControls.style.display = 'grid'; modelControls.style.gap = '6px'; modelControls.append(model, customModel);
  const endpoint = el('input'); endpoint.value = (slot && slot.requires && slot.requires.base_url) || '';
  endpoint.placeholder = 'Provider API base URL';
  endpoint.dataset.auto = endpoint.value ? '0' : '1';
  endpoint.oninput = () => { endpoint.dataset.auto = '0'; };
  const auth = el('select');
  for (const [value, label] of [['api-key', 'API key']]) {
    const option = el('option', null, label); option.value = value; auth.append(option);
  }
  auth.value = 'api-key';
  const credential = el('input'); credential.type = 'password'; credential.autocomplete = 'off';
  credential.placeholder = slot && slot.credential_source && slot.credential_source.startsWith('sealed') ? 'Leave blank to keep current credential' : 'API key, if required';
  const voice = el('input'); voice.value = (slot && slot.requires && slot.requires.voice) || '';
  voice.placeholder = 'Voice, e.g. af_heart or alloy';
  const locale = el('input'); locale.value = (slot && slot.requires && slot.requires.locale) || '';
  locale.placeholder = 'Locale, e.g. en_US';
  const makeDefault = el('input'); makeDefault.type = 'checkbox';
  const makeDefaultLabel = el('label'); makeDefaultLabel.append(makeDefault, document.createTextNode(' Use as the default task model'));
  const clear = el('input'); clear.type = 'checkbox';
  const clearLabel = el('label'); clearLabel.append(clear, document.createTextNode(' Remove the stored credential'));

  let modelInitialized = false;
  const refreshModelChoices = () => {
    const choices = ((inferenceModels[role.value] || {})[provider.value] || []);
    const initial = !modelInitialized && slot && initialProvider === provider.value ? (slot.model || '') : '';
    model.replaceChildren();
    for (const [value, label] of choices) { const option = el('option', null, label); option.value = value; model.append(option); }
    const custom = el('option', null, 'Custom model…'); custom.value = '__custom__'; model.append(custom);
    if (initial && choices.some(([value]) => value === initial)) model.value = initial;
    else if (initial) { model.value = '__custom__'; customModel.value = initial; }
    else if (choices.length) model.value = choices[0][0];
    else model.value = '__custom__';
    customModel.style.display = model.value === '__custom__' ? '' : 'none';
    const needsModel = role.value === 'language' || choices.length > 0;
    model.closest('.field').style.display = needsModel ? '' : 'none';
    if (!needsModel) customModel.style.display = 'none';
    modelInitialized = true;
  };
  model.onchange = () => { customModel.style.display = model.value === '__custom__' ? '' : 'none'; if (model.value === '__custom__') customModel.focus(); };

  const refreshEndpoint = () => {
    const defaultURL = inferenceDefaultBaseURL(role.value, provider.value);
    if (endpoint.dataset.auto === '1' || !endpoint.value.trim()) { endpoint.value = defaultURL; endpoint.dataset.auto = '1'; }
    endpoint.closest('.field').style.display = defaultURL ? '' : 'none';
    endpoint.readOnly = provider.value !== 'openai' && !(role.value === 'embedding' && provider.value === 'ollama');
    endpoint.title = endpoint.readOnly ? 'This provider uses its standard endpoint.' : 'Change this for an OpenAI-compatible or local server.';
  };

  const refreshAuth = () => {
    const anthropic = role.value === 'language' && provider.value === 'anthropic';
    auth.closest('.field').style.display = anthropic ? '' : 'none';
    const claude = role.value === 'language' && provider.value === 'claude-code';
    credential.closest('.field').style.display = claude ? 'none' : '';
    credential.placeholder = slot && slot.credential_source === 'sealed API key'
      ? 'Leave blank to keep current API key'
      : 'API key, if required';
  };

  const refreshProviderChoices = () => {
    const current = provider.value || initialProvider;
    provider.replaceChildren();
    for (const [value, label] of inferenceProviders[role.value]) {
      const option = el('option', null, label); option.value = value; provider.append(option);
    }
    if ([...provider.options].some(o => o.value === current)) provider.value = current;
    const fixedName = { embedding: 'embed', transcription: 'transcribe', speech: 'speak' }[role.value];
    if (fixedName) { name.value = fixedName; name.readOnly = true; }
    else { if (!slot && ['embed', 'transcribe', 'speak'].includes(name.value)) name.value = ''; name.readOnly = false; }
    voice.closest('.field').style.display = role.value === 'speech' ? '' : 'none';
    locale.closest('.field').style.display = role.value === 'transcription' ? '' : 'none';
    makeDefaultLabel.style.display = role.value === 'language' ? '' : 'none';
    modelInitialized = false;
    refreshModelChoices();
    refreshEndpoint();
    refreshAuth();
  };

  form.append(field('Role', role), field('Connection name', name, 'Routing refers to this stable name.'),
    field('Provider', provider), field('Model', modelControls),
    field('Base URL', endpoint, 'Provider defaults are prefilled. OpenAI-compatible and local endpoints remain editable.'),
    field('Authentication', auth, 'Anthropic API connections use API billing. Claude Code uses the account already signed in to the Claude CLI on this Mac.'),
    field('Credential', credential, 'API keys are encrypted to this agent before they are written.'),
    field('Voice', voice), field('Locale', locale));
  const flags = el('div', 'wide row'); flags.append(makeDefaultLabel);
  if (slot && slot.credential_source && slot.credential_source.startsWith('sealed')) flags.append(clearLabel);
  form.append(flags);
  const actions = el('div', 'connection-actions');
  const save = el('button', 'btn solid', slot ? 'Save connection' : 'Add connection');
  const status = el('span', 'meta', legacyClaude ? 'Ready to migrate to this Mac’s Claude Code sign-in.' : ''); actions.append(save, status);
  if (slot) {
    const remove = el('button', 'btn danger', 'Remove'); let armed = false;
    remove.onclick = async () => {
      if (!armed) { armed = true; remove.textContent = 'Remove connection'; status.textContent = 'This change will require approval.'; return; }
      remove.disabled = true;
      const r = await j(api('/inference/' + encodeURIComponent(slot.name)), { method: 'DELETE' });
      status.textContent = r.ok ? 'Removed. Review and approve the change.' : 'Could not remove: ' + r.error;
      if (r.ok) { await loadRoster(); afterSave(); }
      else remove.disabled = false;
    };
    actions.append(remove);
  }
  form.append(actions);
  role.onchange = () => { endpoint.dataset.auto = '1'; refreshProviderChoices(); };
  provider.onchange = () => { endpoint.dataset.auto = '1'; refreshProviderChoices(); };
  auth.onchange = refreshAuth;
  provider.value = initialProvider || inferenceProviders[role.value][0][0];
  refreshProviderChoices();

  const persist = async () => {
    const connectionName = name.value.trim().replace(/\s+/g, '-');
    if (!connectionName) { status.textContent = 'Give this connection a name.'; name.focus(); return; }
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(connectionName)) { status.textContent = 'Use only letters, numbers, dashes, or underscores in the connection name.'; name.focus(); return; }
    name.value = connectionName;
    const chosenModel = model.value === '__custom__' ? customModel.value.trim() : model.value;
    if (role.value === 'language' && !chosenModel) { status.textContent = 'Choose a model or enter a custom model identifier.'; customModel.focus(); return; }
    const requires = Object.assign({}, (slot && slot.requires) || {});
    if (endpoint.value.trim()) requires.base_url = endpoint.value.trim(); else delete requires.base_url;
    if (provider.value === 'anthropic') {
      requires.auth = 'api-key';
      delete requires.oauth_profile;
    } else { delete requires.auth; delete requires.oauth_profile; }
    if (provider.value === 'claude-code') delete requires.base_url;
    if (voice.value.trim()) requires.voice = voice.value.trim(); else delete requires.voice;
    if (locale.value.trim()) requires.locale = locale.value.trim(); else delete requires.locale;
    save.disabled = true;
    status.textContent = credential.value ? 'Encrypting credential…' : 'Saving…';
    const r = await j(api('/inference'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        original_name: slot ? slot.name : null,
        name: connectionName, provider: provider.value, model: chosenModel || null,
        credential: credential.value || null, clear_credential: clear.checked || legacyClaude,
        requires, set_default: makeDefault.checked,
      }),
    });
    credential.value = ''; save.disabled = false;
    status.textContent = r.ok ? 'Saved. Review and approve the change.' : 'Could not save: ' + r.error;
    if (r.ok) { await loadRoster(); afterSave(); }
  };
  save.onclick = persist;
  return form;
}

function inferenceSource(slot, routing, rerender) {
  const item = el('article', 'source-item');
  const head = el('div', 'source-head');
  const identity = el('div');
  identity.append(el('div', 'source-name', slot.name), el('div', 'source-role', inferenceRoleLabel[slot.role] || slot.role));
  const detail = el('div', 'source-detail');
  detail.append(el('div', null, `${inferenceProviderLabel(slot.provider)}${slot.model ? ' · ' + slot.model : ''}`),
    el('div', null, `${inferenceEndpoint(slot)} · credential: ${slot.credential_source}`));
  if (routing.default === slot.name) detail.append(el('div', 'risk', 'Default route for tasks'));
  const state = el('div', 'source-state');
  const stateName = (slot.status && slot.status.state) || 'unavailable';
  state.append(el('span', 'state ' + stateName, stateName === 'ready' ? 'Verified locally' : stateName));
  state.append(el('div', 'source-detail', (slot.status && slot.status.detail) || 'No diagnostic available'));
  head.append(identity, detail, state); item.append(head);
  const edit = el('details'); edit.append(el('summary', null, 'Edit route'), inferenceForm(slot, rerender));
  item.append(edit);
  return item;
}

async function renderInference(c) {
  const d = await j(api('/inference'));
  const head = el('div', 'page-head');
  head.append(el('div', 'eyebrow', 'Model routing'),
    el('h2', 'page-title', 'Inference'),
    el('p', 'page-lede', 'Choose which models this agent uses to think, remember, hear, and speak. Claude Code routes share the account signed in on this Mac; API providers keep agent-sealed credentials.'));
  c.append(head);
  if (!d.ok) { c.append(el('div', 'ev err', 'Could not load inference setup: ' + d.error)); return; }
  const slots = d.slots || [], routing = d.routing || {};
  const language = slots.filter(s => s.role === 'language');
  const support = slots.filter(s => s.role !== 'language');
  const verified = slots.filter(s => s.status && s.status.state === 'ready').length;
  c.append((() => { const m = el('div', 'metrics'); m.append(metric('Task models', language.length), metric('Supporting engines', support.length), metric('Verified locally', verified), metric('Default route', routing.default || 'Not set')); return m; })());

  const claudeRoutes = language.filter(s => s.provider === 'claude-code');
  if (claudeRoutes.length) {
    const account = section('Claude Code on this Mac', 'One host account serves every Claude Code route. Each route only chooses a model and routing name.');
    const status = claudeRoutes.find(s => s.status && s.status.state === 'ready') || claudeRoutes[0];
    account.append(kv('Account', (status.status && status.status.detail) || 'Claude Code sign-in is unavailable'),
      kv('Used by', claudeRoutes.map(s => s.name).join(', ')));
    c.append(account);
  }

  const rerender = () => setTimeout(render, 350);
  const task = section('Task models', 'Language models receive prompts and may call granted capabilities. “Configured” means a credential is present; Apiary avoids a billable probe.');
  const taskList = el('div', 'source-list');
  for (const slot of language) taskList.append(inferenceSource(slot, routing, rerender));
  if (!language.length) taskList.append(el('div', 'none', 'No task model is configured.'));
  task.append(taskList);
  if (language.length) {
    const select = el('select');
    for (const slot of language) { const option = el('option', null, slot.name); option.value = slot.name; select.append(option); }
    select.value = routing.default || '';
    const save = el('button', 'btn', 'Set default'); const status = el('span', 'meta', '');
    const line = el('div', 'route-line'); line.append(select, save, status); task.append(line);
    save.onclick = async () => {
      save.disabled = true;
      const r = await j(api('/inference/default'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: select.value }) });
      save.disabled = false; status.textContent = r.ok ? 'Saved. Approval required.' : 'Could not save: ' + r.error;
      if (r.ok) { await loadRoster(); rerender(); }
    };
  }
  const add = el('details', 'technical'); add.append(el('summary', null, 'Add a model route'), inferenceForm(null, rerender));
  task.append(add); c.append(task);

  const equipment = section('Memory and voice', 'Supporting engines have reserved roles: embed builds semantic memory, transcribe hears audio, and speak renders voice replies.');
  const supportList = el('div', 'source-list');
  for (const slot of support) supportList.append(inferenceSource(slot, routing, rerender));
  if (!support.length) supportList.append(el('div', 'none', 'No supporting engines are configured.'));
  equipment.append(supportList); c.append(equipment);

  const policy = section('Routing policy', 'Routing is decided before inference. Human-approved floors win, then task rules, then the default model.');
  if (!(routing.floors || []).length && !(routing.rules || []).length) policy.append(el('div', 'none', 'No conditional routes. Every task uses the default model.'));
  for (const rule of routing.floors || []) policy.append(kv('Required floor', `${rule.when} → ${rule.to}`));
  for (const rule of routing.rules || []) policy.append(kv('Task rule', `${rule.when} → ${rule.to}`));
  const advanced = el('button', 'btn', 'Edit advanced routing'); advanced.onclick = () => openTab('manifest');
  policy.append(advanced); c.append(policy);
}

// ------------------------------------------------------------ run

function renderRun(c) {
  c.append(help('One governed task. The stream below is AG-UI presence (steps, tool calls, text); the signed log is truth — every model call lands as a signed checkpoint entry. Budget reservations are taken before the call and settled after.'));
  const box = el('div'); box.id = 'runbox';
  const ta = el('textarea'); ta.id = 'task'; ta.placeholder = 'task for this agent…';
  ta.setAttribute('aria-label', 'Task');
  const go = el('button', null, 'Run task'); go.id = 'go';
  box.append(ta, go);
  const row = el('div', 'row');
  const cls = el('input'); cls.placeholder = 'class (optional, e.g. reasoning)';
  const dcls = el('input'); dcls.placeholder = 'data class (optional, e.g. sensitive)';
  cls.setAttribute('aria-label', 'Routing class');
  dcls.setAttribute('aria-label', 'Data class');
  row.append(cls, dcls);
  c.append(box, row,
    help('class picks a routing rule from the manifest (which model slot handles this kind of task). data class engages routing floors — e.g. a "sensitive" floor can pin such tasks to a local model regardless of what routing would prefer.'));
  const events = el('div'); events.id = 'events';
  c.append(events);
  go.onclick = () => runTask(ta, go, events, cls.value.trim() || null, dcls.value.trim() || null);
}

function ev(events, cls, text) {
  const node = el('div', 'ev ' + cls, text);
  events.append(node);
  node.scrollIntoView({ block: 'nearest' });
  return node;
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
    let responseNode = null;
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
          case 'TEXT_MESSAGE_CONTENT':
            if (!responseNode) responseNode = ev(events, 'text', '');
            responseNode.textContent += e.delta;
            responseNode.scrollIntoView({ block: 'nearest' });
            break;
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
  if (!d.ok) { c.append(el('div', 'ev err', 'Could not load configuration: ' + d.error)); return; }
  const head = el('div', 'page-head');
  head.append(el('div', 'eyebrow', d.ratified ? 'Approved configuration' : 'Draft configuration'),
    el('h2', 'page-title', 'Configuration'),
    el('p', 'page-lede', 'Advanced editing for models, routing, memory, limits, governance, and host coordination. Saving creates a draft for separate review and approval.'));
  c.append(head);

  const guide = el('details');
  guide.append(el('summary', null, 'Configuration field guide'));
  const g = el('div');
  const rows = [
    ['identity.npub', 'the agent’s public key — immutable; the host refuses an amendment that changes it'],
    ['inference[]', 'agent-owned inference connections. Task-model names are routing targets; reserved names embed, transcribe, and speak provide semantic memory and voice equipment. Manage ordinary changes from Inference. Per-slot credentials are NIP-44-sealed.'],
    ['routing.default', 'slot used when no rule matches'],
    ['routing.rules[]', 'conditional slot choices, e.g. {when: task.class == "reasoning", to: workhorse}'],
    ['routing.floors[]', 'human-owned clamps, e.g. {when: data.class == "sensitive", to: local} — routing may be stricter than a floor, never looser'],
    ['connectors[]', 'what the agent may touch, default-deny. Each entry: {type, caps, credential?}. Managed from Capabilities: host library holds configurations, grants are per-agent amendments with credentials sealed to this agent alone.'],
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
  ed.setAttribute('aria-label', 'Manifest YAML');
  const row = el('div', 'row');
  const save = el('button', 'btn solid', 'Save changes for review');
  const status2 = el('span', 'meta', '');
  row.append(save, status2);
  c.append(ed, row);
  c.append(help('Saving pauses the agent until these changes pass the review-and-approve step.'));
  save.onclick = async () => {
    save.disabled = true; status2.textContent = 'Validating…';
    const r = await j(api('/manifest'), {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ yaml: ed.value }),
    });
    save.disabled = false;
    status2.textContent = r.ok ? 'Saved. Review the changes above.' : `Could not save: ${r.error}`;
    if (r.ok) { await loadRoster(); render(); }
  };

  const ext = el('details', 'technical');
  ext.append(el('summary', null, 'Approve with an external signing key'));
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
    exSt.textContent = r.ok
      ? (r.snapshot_warning ? 'Approved, but the review snapshot could not be saved: ' + r.snapshot_warning : 'Approved by ' + r.ratified_by.slice(0, 12) + '…')
      : 'Could not import approval: ' + r.error;
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

// ------------------------------------------------------------ routines

function whenText(r) {
  if (r.every) return `every ${r.every}`;
  if (r.at) return `once at ${r.at} (${r.tz})`;
  return `${r.when} (${r.tz})`;
}
function tsText(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const diff = (d - Date.now()) / 1000;
  const abs = Math.abs(diff);
  const rel = abs < 90 ? `${Math.round(abs)}s` : abs < 5400 ? `${Math.round(abs / 60)}m` : abs < 172800 ? `${Math.round(abs / 3600)}h` : `${Math.round(abs / 86400)}d`;
  return `${d.toLocaleString()} (${diff >= 0 ? 'in ' + rel : rel + ' ago'})`;
}

async function renderRoutines(c) {
  await proposalBanner(c);
  const d = await j(api('/routines'));
  if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }
  const sec = section('Routines',
    'Standing instructions the governor ratified once; the host replays them on schedule. Time is the only door with no human on the other side, so a routine’s authority comes from ratification — a chat message can never plant one. Each fire is an ordinary governed run (same floors, budget, signed log), on exactly one host (the lease), never overlapping. Keep them small and bounded.');
  if (!d.coordinated) sec.append(help('This agent declares no memory.log_relays — routines run without cross-host coordination (fine for one host; add relays before running the agent on two).'));
  if (!(d.routines || []).length) sec.append(kv('routines', 'none yet — add one below, then ratify in Configuration'));
  for (const r of d.routines) {
    const box = el('div', 'ev');
    const head = el('div', 'row');
    const flag = !r.enabled ? ' · disabled' : r.paused ? ' · PAUSED on this host' : r.spent ? ' · spent (one-shot fired)' : r.running ? ' · running now' : '';
    head.append(el('b', null, r.name), el('span', 'meta', whenText(r) + flag));
    box.append(head);
    box.append(kv('task', r.task));
    box.append(kv('deliver', (r.deliver || []).length ? r.deliver.map(x => x.telegram ? `telegram ${x.telegram}${x.as_voice ? ' (voice)' : ''}` : x.buzz ? `buzz #${x.buzz}` : x.nostr ? 'nostr publish' : x.companion ? `companion${x.as_voice ? ' (voice)' : ''}` : '?').join(', ') : 'log only'));
    box.append(kv('next fire', r.schedule_error ? 'schedule error: ' + r.schedule_error : tsText(r.next_fire)));
    if (r.preview && r.preview.length) box.append(kv('then', r.preview.slice(1).map(p => new Date(p).toLocaleString()).join(' · ')));
    box.append(kv('last', r.last_fired ? `${tsText(r.last_fired)} → ${r.last_outcome || '?'}` : 'never'));
    if (r.last_delivery && r.last_delivery.length) box.append(kv('delivered', JSON.stringify(r.last_delivery)));
    box.append(kv('fires · budget', `${r.fires} · ${r.budget && r.budget.tokens_per_run ? r.budget.tokens_per_run + ' tokens/run' : 'default reservation'} · catch_up ${r.catch_up}`));
    if (r.note) box.append(kv('supervisor', r.note));
    const acts = el('div', 'row');
    const run = el('button', 'btn solid', 'RUN NOW');
    const pause = el('button', 'btn', r.paused ? 'RESUME' : 'PAUSE');
    const st = el('span', 'meta', '');
    acts.append(run, pause, st);
    box.append(acts);
    sec.append(box);
    run.onclick = async () => {
      st.textContent = 'firing… (governed run + delivery)';
      run.disabled = true;
      const res = await j(api('/routines/' + encodeURIComponent(r.name) + '/run'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      st.textContent = res.ok ? `→ ${res.outcome}; delivered ${JSON.stringify(res.delivered)}` : 'failed: ' + res.error;
      run.disabled = false;
      setTimeout(render, 1500);
    };
    pause.onclick = async () => {
      const res = await j(api('/routines/' + encodeURIComponent(r.name) + '/' + (r.paused ? 'resume' : 'pause')), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      st.textContent = res.ok ? (res.paused ? 'paused on this host (schedule stays in the manifest)' : 'resumed') : 'failed: ' + res.error;
      render();
    };
  }
  c.append(sec);

  // ---- add form → appends to manifest YAML, PUTs it; ratify afterward
  const add = section('Add a routine',
    'Writes an amendment to the manifest — re-ratify in Configuration afterward. Times are in the zone you pick; cron is standard 5-field (min hour day month weekday, Sunday = 0).');
  const fName = el('input'); fName.placeholder = 'name (e.g. morning-brief)';
  const fKind = el('select');
  for (const [v, t] of [['when', 'cron'], ['every', 'every (15m, 2h, 1d)'], ['at', 'once at (YYYY-MM-DDTHH:MM)']]) { const o = el('option', null, t); o.value = v; fKind.append(o); }
  const fWhen = el('input', 'grow'); fWhen.placeholder = '0 8 * * 1-5';
  const fTz = el('input'); fTz.placeholder = 'tz (America/Chicago)'; fTz.value = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  const fTask = el('textarea'); fTask.rows = 3; fTask.placeholder = 'the standing instruction — what should the agent do each time?';
  const fDeliverKind = el('select');
  for (const [v, t] of [['', 'log only (no delivery)'], ['telegram', 'telegram chat id'], ['buzz', 'buzz channel'], ['nostr', 'nostr publish'], ['companion', 'companion (spoken by apiary-voice)']]) { const o = el('option', null, t); o.value = v; fDeliverKind.append(o); }
  const fDeliverTo = el('input', 'grow'); fDeliverTo.placeholder = 'chat id / channel';
  const fVoice = el('input'); fVoice.type = 'checkbox'; fVoice.style.width = 'auto';
  const voiceLabel = el('label', null, ' as voice'); voiceLabel.prepend(fVoice);
  const fBudget = el('input'); fBudget.placeholder = 'tokens/run (e.g. 8000)'; fBudget.value = '8000';
  const go = el('button', 'btn solid', 'ADD (AMEND MANIFEST)');
  const st = el('span', 'meta', '');
  const r1 = el('div', 'row'); r1.append(fName, fKind, fWhen, fTz);
  const r2 = el('div', 'row'); r2.append(fDeliverKind, fDeliverTo, voiceLabel, fBudget);
  const r3 = el('div', 'row'); r3.append(go, st);
  add.append(r1, help('cron: standard 5 fields (Sunday = 0). every: 15m/2h/1d, minimum 1m, no tz needed. at: one-shot, disables itself after firing.'), fTask, r2, r3);
  c.append(add);
  fKind.onchange = () => { fWhen.placeholder = fKind.value === 'when' ? '0 8 * * 1-5' : fKind.value === 'every' ? '30m' : '2026-08-17T15:00'; };
  go.onclick = async () => {
    const name = fName.value.trim().replace(/[^A-Za-z0-9_-]/g, '-');
    if (!name || !fWhen.value.trim() || !fTask.value.trim()) { st.textContent = 'name, schedule, and task are required'; return; }
    const m = await j(api('/manifest'));
    if (!m.ok) { st.textContent = 'failed: ' + m.error; return; }
    let yaml = m.yaml.replace(/\s+$/, '');
    const q = s => JSON.stringify(String(s));
    let entry = `- name: ${name}\n`;
    entry += `  ${fKind.value}: ${q(fWhen.value.trim())}\n`;
    if (fKind.value !== 'every') entry += `  tz: ${q(fTz.value.trim() || 'UTC')}\n`;
    entry += `  task: |\n` + fTask.value.trim().split('\n').map(l => '    ' + l).join('\n') + '\n';
    if (fDeliverKind.value) {
      entry += `  deliver:\n`;
      if (fDeliverKind.value === 'companion') entry += `  - companion: true\n`;
      else if (fDeliverKind.value === 'nostr') entry += `  - nostr: publish\n`;
      else entry += `  - ${fDeliverKind.value}: ${q(fDeliverTo.value.trim())}\n`;
      if (fVoice.checked) entry += `    as_voice: true\n`;
    }
    if (fBudget.value.trim()) entry += `  budget:\n    tokens_per_run: ${parseInt(fBudget.value, 10) || 8000}\n`;
    if (/^routines:\s*$/m.test(yaml)) yaml += '\n' + entry;
    else if (/^routines:/m.test(yaml)) yaml += '\n' + entry;
    else yaml += '\nroutines:\n' + entry;
    const r = await j(api('/manifest'), { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ yaml }) });
    st.textContent = r.ok ? `added ${name} — now ratify in Configuration` : 'failed: ' + r.error;
    if (r.ok) { loadRoster(); setTimeout(render, 800); }
  };
}

async function renderConnectors(c) {
  const lib = await j('/api/connectors');
  if (!lib.ok) { c.append(el('div', 'ev err', 'error: ' + lib.error)); return; }
  const d = await j(api('/manifest'));
  if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }

  // ---- this agent's grants
  const gSec = section('Grants',
    'A grant copies a host-library entry into this agent’s manifest, sealing any secret to this agent alone. Every grant or revoke is an amendment — re-ratify in Configuration afterward.');
  const grants = (d.manifest.connectors || []);
  if (!grants.length) gSec.append(kv('grants', 'none — the agent can think and speak, not act'));
  for (const g of grants) {
    const box = el('div', 'ev');
    const row = el('div', 'row');
    const title = (g.caps && g.caps.library_name) || (g.caps && g.caps.vaults && g.caps.vaults[0] && g.caps.vaults[0].name) || g.type;
    row.append(el('b', null, title), el('span', 'meta', connectorKindLabel[g.type] || g.type), el('span', 'meta', g.credential ? 'credential sealed to this agent' : 'no credential'));
    row.append(el('span', 'grow', ''));
    const rv = el('button', 'btn danger', 'REVOKE');
    row.append(rv);
    box.append(row);
    connectorDetails(box, g.type, g.caps || {}, async (mode, select) => {
      const previous = connectorAccessMode(g.type, g.caps || {});
      const caps = {}; setConnectorAccess(g.type, caps, mode);
      select.disabled = true;
      const r = await j(api('/connectors/' + encodeURIComponent(g.type) + '/caps'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ caps }) });
      select.disabled = false;
      if (!r.ok) select.value = previous;
      else setConnectorAccess(g.type, g.caps || (g.caps = {}), mode);
      gStatus.textContent = r.ok ? `${mode === 'read-write' ? 'read + write enabled' : 'read-only'} — re-ratify in Configuration` : 'failed: ' + r.error;
      if (r.ok) loadRoster();
    });
    rv.onclick = async () => {
      const r = await j(api('/connectors/' + encodeURIComponent(g.type)), { method: 'DELETE' });
      gStatus.textContent = r.ok ? `revoked ${g.type} — re-ratify in Configuration` : 'failed: ' + r.error;
      loadRoster(); render();
    };
    if (g.type === 'mcp') {
      // Discover with THIS agent's sealed credential (post-OAuth), tick, apply.
      const dRow = el('div', 'row');
      const disc = el('button', 'btn', 'DISCOVER TOOLS');
      const dSt = el('span', 'meta', '');
      dRow.append(disc, dSt);
      const toolsBox = el('div');
      box.append(dRow, toolsBox);
      disc.onclick = async () => {
        dSt.textContent = 'probing with this agent’s credential…';
        const key = (g.caps && (g.caps.library_name || g.caps.url || g.caps.command)) || 'mcp';
        const r = await j(api('/connectors/' + encodeURIComponent(key) + '/discover'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
        if (!r.ok) { dSt.textContent = 'failed: ' + r.error; return; }
        const allowed = new Set(g.caps.allowed_tools || []);
        const picked = new Set(allowed);
        const readOnly = connectorAccessMode('mcp', g.caps || {}) === 'read-only';
        toolsBox.replaceChildren();
        dSt.textContent = `${r.tools.length} tools — ${readOnly ? 'only explicitly read-only tools are available' : 'tick what this agent may use'}`;
        toolsBox.append(help('MCP read/write labels are supplied by the server. Apiary treats missing readOnlyHint as write-capable.'));
        for (const t of r.tools) {
          const unavailable = readOnly && !t.read_only;
          if (unavailable) picked.delete(t.name);
          const cb = el('input'); cb.type = 'checkbox'; cb.style.width = 'auto'; cb.disabled = unavailable; cb.checked = !unavailable && (allowed.has('*') || allowed.has(t.name));
          const lab = el('label', null, ` ${t.name} · ${t.read_only ? 'read only' : 'may write'}${t.description ? ' — ' + t.description.slice(0, 120) : ''}`); lab.prepend(cb); lab.style.display = 'block';
          cb.onchange = () => { if (cb.checked) picked.add(t.name); else picked.delete(t.name); picked.delete('*'); };
          toolsBox.append(lab);
        }
        const apply = el('button', 'btn solid', 'APPLY ALLOWLIST (AMEND)');
        const aSt = el('span', 'meta', '');
        const aRow = el('div', 'row'); aRow.append(apply, aSt);
        toolsBox.append(aRow);
        apply.onclick = async () => {
          const rr = await j(api('/connectors/mcp/allowed_tools'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tools: [...picked] }) });
          aSt.textContent = rr.ok ? 'applied — re-ratify in Configuration' : 'failed: ' + rr.error;
          if (rr.ok) { loadRoster(); setTimeout(render, 800); }
        };
      };
    }
    gSec.append(box);
  }
  const gRow = el('div', 'row');
  const gSel = el('select');
  for (const e of (lib.library || [])) {
    const o = el('option', null, `${e.name} (${e.kind})`);
    o.value = e.name; gSel.append(o);
  }
  if (!(lib.library || []).length) gSel.append(el('option', null, 'library is empty — open it above to add entries'));
  const gCred = el('input', 'grow'); gCred.type = 'password';
  gCred.placeholder = 'secret to seal to this agent (optional)';
  const gGo = el('button', 'btn solid', 'GRANT');
  const gStatus = el('span', 'meta', '');
  gRow.append(gSel, gCred, gGo, gStatus);
  gSec.append(gRow,
    help('The secret (if any) is sealed with NIP-44 to this agent’s key at grant time and lands in the manifest as a blob — never stored anywhere else, unreadable by other agents or hosts.'));
  c.append(gSec);
  const updateGrantHint = () => {
    const entry = (lib.library || []).find(e => e.name === gSel.value);
    const catalog = (lib.catalog || []).find(item => entry && entry.caps && entry.caps.catalog_id === item.id);
    gCred.placeholder = catalog && catalog.credential_label
      ? catalog.credential_label + ' — encrypted for this agent'
      : 'secret to seal to this agent (optional)';
  };
  gSel.onchange = updateGrantHint; updateGrantHint();
  gGo.onclick = async () => {
    if (!gSel.value) return;
    const entry = (lib.library || []).find(e => e.name === gSel.value);
    const catalog = (lib.catalog || []).find(item => entry && entry.caps && entry.caps.catalog_id === item.id);
    const needsCredential = catalog && catalog.setup === 'credential';
    if (needsCredential && !gCred.value) {
      gStatus.textContent = `${catalog.credential_label || 'credential'} required`;
      gCred.focus();
      return;
    }
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
          gStatus.textContent = 'granted via OAuth — re-ratify in Configuration';
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
    gStatus.textContent = r.ok ? `granted ${r.kind} — re-ratify in Configuration` : 'failed: ' + r.error;
    gCred.value = '';
    loadRoster(); if (r.ok) render();
  };


}

// ------------------------------------------------------------ host library (host-scoped, all agents)

/// Detail rows for a connector's caps, one fact per line, into `card`.
/// `onAccess(mode, select)` renders an editable access selector when the
/// connector can provide both read-only and read/write behavior.
function connectorDetails(card, kind, caps, onAccess) {
  caps = caps || {};
  if (kind === 'obsidian' || kind === 'markdown-vault') {
    for (const v of (caps.vaults || [])) card.append(kv(v.name, v.path));
    const row = el('div', 'kv');
    const val = el('span', 'v');
    if (onAccess) {
      const select = accessSelect(connectorAccessMode(kind, caps));
      select.onchange = () => onAccess(select.value, select);
      val.append(select);
    } else val.textContent = caps.write ? 'Read + write' : 'Read only';
    row.append(el('span', 'k', 'access'), val); card.append(row);
  } else if (kind === 'mcp') {
    card.append(kv('transport', caps.transport === 'http' ? `remote · ${caps.url}` : `local · ${caps.command || '?'} ${(caps.args || []).join(' ')}`.trim()));
    if (caps.oauth_client_id) card.append(kv('auth', 'OAuth (sign-in at grant)'));
    const mode = connectorAccessMode(kind, caps);
    if (onAccess && connectorSupportsReadWrite(kind, caps)) {
      const select = accessSelect(mode); select.onchange = () => onAccess(select.value, select);
      const accessRow = el('div', 'kv'); const value = el('span', 'v'); value.append(select);
      accessRow.append(el('span', 'k', 'access'), value); card.append(accessRow);
    } else card.append(kv('access', mode === 'read-only' ? 'Read only' : 'Read + write'));
    const tools = caps.allowed_tools || [];
    const tv = el('span', 'v');
    if (!tools.length) tv.textContent = 'none allowed';
    else if (tools.includes('*')) tv.textContent = 'all tools (*)';
    else for (const t of tools) { const chip = el('span', 'chip', t); chip.style.marginRight = '4px'; tv.append(chip); }
    const row = el('div', 'kv'); row.append(el('span', 'k', 'tools'), tv); card.append(row);
  } else if (kind === 'nostr-publish') {
    card.append(kv('access', 'Write only · publish public notes'), kv('relays', (caps.relays || []).join(', ')));
  } else if (kind === 'web-search') {
    card.append(kv('provider', caps.provider === 'brave' || !caps.provider ? 'Brave Search API' : caps.provider),
      kv('results', `up to ${caps.max_results || 10} per search`),
      kv('region', `${caps.country || 'US'} · ${caps.search_lang || 'en'}`),
      kv('SafeSearch', caps.safesearch || 'moderate'),
      kv('page reader', caps.fetch_public_pages ? 'all public HTTPS pages included' : 'not included'));
  } else if (kind === 'web-fetch') {
    card.append(kv('access', caps.allow_all_public ? 'all public HTTPS websites' : (caps.allowed_domains || []).join(', ')));
    if (!caps.allow_all_public) card.append(kv('subdomains', caps.allow_subdomains ? 'allowed' : 'not allowed'));
    card.append(kv('safety', 'private and special-use networks blocked'),
      kv('response limit', `${Math.round((caps.max_bytes || 262144) / 1024)} KiB`));
  } else if (kind === 'files') {
    for (const root of (caps.roots || [])) card.append(kv(root.name, root.path));
    card.append(kv('access', 'read-only'), kv('file types', (caps.extensions || []).join(', ')));
  } else if (kind === 'git') {
    for (const repo of (caps.repos || [])) card.append(kv(repo.name, repo.path));
    card.append(kv('access', 'read-only · no hooks or external diff programs'));
  } else {
    card.append(kv('caps', JSON.stringify(caps)));
  }
}

function capsSummary(kind, caps) {
  if (kind === 'obsidian' || kind === 'markdown-vault') {
    const v = (caps.vaults || []).map(x => `${x.name} → ${x.path}`).join('; ');
    return `${v || 'no vaults'}${caps.write ? ' · writable' : ' · read-only'}`;
  }
  if (kind === 'mcp') {
    const where = caps.transport === 'http' ? caps.url : `${caps.command || '?'} ${(caps.args || []).join(' ')}`.trim();
    const tools = (caps.allowed_tools || []).join(', ') || 'no tools allowed';
    const access = connectorAccessMode(kind, caps) === 'read-only' ? 'Read only' : 'Read + write';
    return `${where}${caps.oauth_client_id ? ' · OAuth' : ''} · ${access} · tools: ${tools}`;
  }
  if (kind === 'nostr-publish') return `relays: ${(caps.relays || []).join(', ')}`;
  if (kind === 'web-search') return `Brave Search · up to ${caps.max_results || 10} results · ${caps.country || 'US'}/${caps.search_lang || 'en'}${caps.fetch_public_pages ? ' · public page reader included' : ''}`;
  if (kind === 'web-fetch') return caps.allow_all_public
    ? 'all public HTTPS websites · private networks blocked'
    : `HTTPS: ${(caps.allowed_domains || []).join(', ') || 'no domains'}`;
  if (kind === 'files') return `${(caps.roots || []).map(x => `${x.name} → ${x.path}`).join('; ') || 'no roots'} · read-only`;
  if (kind === 'git') return `${(caps.repos || []).map(x => `${x.name} → ${x.path}`).join('; ') || 'no repositories'} · read-only`;
  return JSON.stringify(caps);
}

async function renderLibrary(c) {
  c.append(help('Host-scoped: named connector configurations (kind + caps — never secrets), shared by all agents. Grant from an agent’s Capabilities; each grant is a ratified amendment for that agent alone.'));
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
    'Kinds this host binds: ' + (lib.host_binds || []).join(', ') + '.');
  const catalogSec = section('Recommended connectors',
    'Trusted templates with narrow defaults. Adding one creates a library entry only; an agent receives nothing until you grant it and ratify the change.');
  const catalogList = el('div', 'catalog-list');
  catalogSec.append(catalogList);
  if (window.__libFlash) {
    const f = el('div', 'ev'); f.style.borderColor = 'var(--amber)';
    f.append(el('b', null, '✓ ' + window.__libFlash));
    lSec.append(f);
    window.__libFlash = null;
  }
  const entries = (lib.library || []).slice();
  const list = el('div');
  const lStatus = el('span', 'meta', '');
  const drawList = () => {
    list.replaceChildren();
    if (!entries.length) { list.append(el('div', 'meta', 'no entries yet — add your first below')); return; }
    entries.forEach((e, i) => {
      const card = el('div', 'ev');
      const head = el('div', 'row');
      head.append(el('b', null, e.name), el('span', 'meta', connectorKindLabel[e.kind] || e.kind));
      const holders = grantsByKind[e.kind] || [];
      const spacer = el('span', 'grow', ''); head.append(spacer);
      const del = el('button', 'btn danger', 'REMOVE');
      head.append(del);
      card.append(head);
      const caps = e.caps || {};
      connectorDetails(card, e.kind, caps, async (mode, select) => {
        const previous = connectorAccessMode(e.kind, caps);
        setConnectorAccess(e.kind, caps, mode); e.caps = caps; select.disabled = true;
        window.__libFlash = `${e.name}: ${mode === 'read-write' ? 'read + write' : 'read-only'} for future grants (existing grants keep their own setting — change it on the agent’s Capabilities)`;
        const ok = await saveLib();
        select.disabled = false;
        if (!ok) { setConnectorAccess(e.kind, caps, previous); select.value = previous; }
      });
      // Who has it, and grant from here.
      const gRow = el('div', 'row');
      gRow.append(el('span', 'meta', holders.length ? 'granted to: ' + holders.join(', ') : 'granted to: nobody yet'));
      const sel = el('select');
      const eligible = agents.filter(a => !holders.includes(a.name || a.npub.slice(0, 12)));
      for (const a of eligible) { const o = el('option', null, a.name || a.npub.slice(0, 12)); o.value = a.npub; sel.append(o); }
      const gBtn = el('button', 'btn', 'GRANT TO ▸');
      const gSt = el('span', 'meta', '');
      if (eligible.length) gRow.append(sel, gBtn, gSt);
      card.append(gRow);
      list.append(card);
      del.onclick = async () => { entries.splice(i, 1); window.__libFlash = `removed ${e.name} (grants already made are untouched)`; await saveLib(); };
      gBtn.onclick = async () => {
        const npub = sel.value; if (!npub) return;
        const needsSecret = e.kind === 'web-search' || (e.kind === 'mcp' && caps.transport === 'http' && !caps.oauth_client_id);
        if (needsSecret) { gSt.textContent = 'this one needs an API key sealed to the agent — grant it from the agent’s Capabilities'; return; }
        gBtn.disabled = true; gSt.textContent = 'granting…';
        const r = await j(`/api/agents/${encodeURIComponent(npub)}/connectors`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: e.name }) });
        gBtn.disabled = false;
        if (r.ok) {
          const who = (agents.find(a => a.npub === npub) || {}).name || npub.slice(0, 12);
          window.__libFlash = `granted ${e.name} to ${who} — ratify on ${who}’s Configuration before it takes effect`;
          loadRoster(); render();
        } else if (r.oauth_url || (r.error && /oauth/i.test(r.error))) {
          gSt.textContent = 'needs OAuth sign-in — grant from the agent’s Capabilities (it opens the flow)';
        } else gSt.textContent = 'failed: ' + r.error;
      };
    });
  };
  // ---- add: a form per kind (JSON is the advanced view, not the way in)
  const addSec = section('Add a connector',
    'Pick a kind and fill in the fields. Nothing here is secret — secrets are sealed to an agent at grant time. Removing a library entry does not revoke grants; those live in agent manifests.');
  const nName = el('input'); nName.placeholder = 'library name (e.g. my-notes)';
  nName.title = 'How this entry is listed in the library and picked when granting to an agent';
  nName.oninput = () => { nName.dataset.auto = ''; };
  const nKind = el('select');
  const kindLabels = {
    'web-search': 'Full web search & research (Brave)',
    'web-fetch': 'Web page reader (open known URLs)',
    'files': 'Files and documents (read-only folders)',
    'git': 'Git repositories (read-only)',
    'obsidian': 'Obsidian vault (memory + notes tools)',
    'markdown-vault': 'Markdown folder (memory + notes tools)',
    'mcp': 'MCP server (tools; stdio or remote/OAuth)',
    'nostr-publish': 'Nostr publish (post notes to relays)',
  };
  for (const k of (lib.host_binds || []).filter(k => k !== 'mock-echo')) { const o = el('option', null, kindLabels[k] || k); o.value = k; nKind.append(o); }
  const kindRow = el('div', 'row'); kindRow.append(nName, nKind);
  const fields = el('div');
  const advanced = el('details');
  advanced.append(el('summary', null, 'advanced: caps as JSON'));
  const nCaps = el('textarea'); nCaps.rows = 3; nCaps.placeholder = '{}';
  advanced.append(nCaps, help('This is exactly what the form writes. Edit it if you know what you want; the form fields above are ignored while this has content.'));
  const nGo = el('button', 'btn solid', 'ADD TO LIBRARY');
  const goRow = el('div', 'row'); goRow.append(nGo, lStatus);
  addSec.append(kindRow, fields, advanced, goRow);
  lSec.append(list);
  c.append(catalogSec, lSec, addSec);

  // Per-kind field builders. Each returns { caps() → object, validate() → error|null }.
  let current = null;
  let selectedCatalogId = null;
  const vaultBuilder = (obsidian) => {
    fields.replaceChildren();
    const rows = [];
    const vaultsBox = el('div');
    const addVault = (name = '', path = '') => {
      const r = el('div', 'row');
      const n = el('input'); n.placeholder = 'vault name (e.g. notes)'; n.value = name;
      const pth = el('input', 'grow'); pth.placeholder = obsidian ? '/Users/you/Obsidian/MyVault' : '/Users/you/repos/some-kb/docs'; pth.value = path;
      const choose = el('button', 'btn', 'CHOOSE…');
      choose.title = 'open the system folder picker';
      choose.onclick = async () => {
        choose.disabled = true;
        const r = await j('/api/host/pick-folder', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
        choose.disabled = false;
        if (r.ok && r.path) {
          pth.value = r.path;
          const slug = r.path.split('/').filter(Boolean).pop().toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
          if (!n.value.trim()) n.value = slug;
          if (!nName.value.trim()) nName.value = slug; // the library entry name, too
        } else if (r.unavailable) { lStatus.textContent = 'no folder picker on this host (headless) — type the path'; }
      };
      n.oninput = () => { if (!nName.value.trim() || nName.dataset.auto === '1') { nName.value = n.value.trim(); nName.dataset.auto = '1'; } };
      const rm = el('button', 'btn', '−');
      r.append(n, pth, choose, rm); vaultsBox.append(r); rows.push({ n, pth, r });
      rm.onclick = () => { r.remove(); rows.splice(rows.findIndex(x => x.r === r), 1); };
    };
    addVault();
    const more = el('button', 'btn', '+ another vault');
    more.onclick = () => addVault();
    const access = accessSelect('read-only');
    fields.append(
      help(obsidian
        ? 'An Obsidian vault is a folder of markdown. Paste the folder path (Finder: right-click the vault → Get Info, or drag it into a Terminal). The agent gets search / read tools (and write, only if you allow it), and the notes also feed its memory retrieval as DATA. Tags, [[wikilinks]] and frontmatter are understood. .obsidian and hidden folders are skipped.'
        : 'Any folder of markdown files — a knowledge-base repo checkout, docs, meeting notes. Same tools as Obsidian without the Obsidian-specific parsing.'),
      vaultsBox, more, field('Access', access, 'Read + write adds create, append, and edit tools. Read only is the default.'),
      help('Paths are jailed: the agent cannot read or write outside the folders you list, even via symlinks. Ceiling 5000 notes per vault.'));
    current = {
      caps: () => ({ vaults: rows.map(x => ({ name: x.n.value.trim(), path: x.pth.value.trim() })).filter(v => v.name && v.path), write: access.value === 'read-write' }),
      validate: () => rows.some(x => x.n.value.trim() && x.pth.value.trim()) ? null : 'add at least one vault (name + path)',
    };
  };
  const namedRootsBuilder = ({ noun, pathHint, helpText }) => {
    const rows = [];
    const box = el('div');
    const addRoot = (name = '', path = '') => {
      const row = el('div', 'row');
      const rootName = el('input'); rootName.placeholder = `${noun} name`; rootName.value = name;
      const rootPath = el('input', 'grow'); rootPath.placeholder = pathHint; rootPath.value = path;
      const choose = el('button', 'btn', 'CHOOSE…'); choose.type = 'button';
      const remove = el('button', 'btn', '−'); remove.type = 'button';
      choose.onclick = async () => {
        choose.disabled = true;
        const picked = await j('/api/host/pick-folder', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
        choose.disabled = false;
        if (picked.ok && picked.path) {
          rootPath.value = picked.path;
          const slug = picked.path.split('/').filter(Boolean).pop().toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
          if (!rootName.value.trim()) rootName.value = slug;
          if (!nName.value.trim() || nName.dataset.auto === '1') { nName.value = slug; nName.dataset.auto = '1'; }
        } else if (picked.unavailable) lStatus.textContent = 'no folder picker on this host (headless) — type the path';
      };
      rootName.oninput = () => {
        if (!nName.value.trim() || nName.dataset.auto === '1') { nName.value = rootName.value.trim(); nName.dataset.auto = '1'; }
      };
      row.append(rootName, rootPath, choose, remove); box.append(row);
      const record = { name: rootName, path: rootPath, row }; rows.push(record);
      remove.onclick = () => { row.remove(); rows.splice(rows.indexOf(record), 1); };
    };
    addRoot();
    const more = el('button', 'btn', `+ another ${noun}`); more.type = 'button'; more.onclick = () => addRoot();
    fields.append(help(helpText), box, more);
    return {
      values: () => rows.map(x => ({ name: x.name.value.trim(), path: x.path.value.trim() })).filter(x => x.name && x.path),
      valid: () => rows.some(x => x.name.value.trim() && x.path.value.trim()),
    };
  };
  const webBuilder = () => {
    fields.replaceChildren();
    const restrict = el('input'); restrict.type = 'checkbox'; restrict.style.width = 'auto';
    const restrictLabel = el('label', null, ' restrict access to specific domains'); restrictLabel.prepend(restrict);
    const domains = el('textarea'); domains.rows = 3; domains.placeholder = 'docs.example.com\napi.example.com';
    const subdomains = el('input'); subdomains.type = 'checkbox'; subdomains.style.width = 'auto';
    const subdomainsLabel = el('label', null, ' also allow subdomains of each domain'); subdomainsLabel.prepend(subdomains);
    const domainBox = el('div'); domainBox.style.display = 'none';
    domainBox.append(field('Approved domains', domains, 'One per line or comma-separated. Exact hosts only unless you allow subdomains.'), subdomainsLabel);
    const maxKiB = el('input'); maxKiB.type = 'number'; maxKiB.min = '16'; maxKiB.max = '2048'; maxKiB.value = '256';
    const limitRow = el('div', 'row'); limitRow.append(field('Maximum response (KiB)', maxKiB, '16–2048 KiB'));
    restrict.onchange = () => { domainBox.style.display = restrict.checked ? '' : 'none'; if (restrict.checked) domains.focus(); };
    fields.append(
      help('By default the agent may read any public HTTPS website. DNS is resolved and pinned for every request; loopback, private, link-local, and other special-use networks stay blocked, including after redirects.'),
      restrictLabel, domainBox, limitRow);
    const parsed = () => domains.value.split(/[\s,]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
    current = {
      caps: () => ({ allow_all_public: !restrict.checked, allowed_domains: restrict.checked ? [...new Set(parsed())] : [], allow_subdomains: restrict.checked && subdomains.checked, max_bytes: Number(maxKiB.value) * 1024 }),
      validate: () => {
        if (restrict.checked && !parsed().length) return 'add at least one approved domain or turn off the restriction';
        if (restrict.checked && parsed().some(x => !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))) return 'domains must be host names only (no scheme, port, or path)';
        const size = Number(maxKiB.value);
        return Number.isFinite(size) && size >= 16 && size <= 2048 ? null : 'response limit must be between 16 and 2048 KiB';
      },
    };
  };
  const webSearchBuilder = () => {
    fields.replaceChildren();
    const country = el('input'); country.value = 'US'; country.maxLength = 2; country.placeholder = 'US';
    const language = el('input'); language.value = 'en'; language.maxLength = 5; language.placeholder = 'en';
    const maxResults = el('input'); maxResults.type = 'number'; maxResults.min = '1'; maxResults.max = '20'; maxResults.value = '10';
    const safe = el('select');
    for (const [value, label] of [['moderate', 'Moderate (recommended)'], ['strict', 'Strict'], ['off', 'Off']]) { const option = el('option', null, label); option.value = value; safe.append(option); }
    const fetch = el('input'); fetch.type = 'checkbox'; fetch.style.width = 'auto'; fetch.checked = true;
    const fetchLabel = el('label', null, ' include the public HTTPS page reader for full research'); fetchLabel.prepend(fetch);
    const localeRow = el('div', 'row'); localeRow.append(field('Result country', country, 'Two-letter country code'), field('Search language', language, 'Language code'));
    fields.append(
      help('Adds a real search-engine tool backed by the Brave Search API. The API key is not stored in this library entry; paste it only when granting the connector to an agent, where it is encrypted to that agent.'),
      localeRow,
      field('Maximum results per query', maxResults, '1–20; the agent may request fewer'),
      field('SafeSearch', safe, 'Applied by the provider to every query'),
      fetchLabel,
      help('With the page reader enabled, one grant supplies both web_search for discovery and web_fetch for reading sources. Private and special-use networks remain blocked.'));
    current = {
      caps: () => ({ provider: 'brave', country: country.value.trim().toUpperCase(), search_lang: language.value.trim().toLowerCase(), safesearch: safe.value, max_results: Number(maxResults.value), fetch_public_pages: fetch.checked, fetch_max_bytes: 262144 }),
      validate: () => {
        if (!/^[A-Za-z]{2}$/.test(country.value.trim())) return 'country must be a two-letter code';
        if (!/^[A-Za-z]{2,3}(?:-[A-Za-z]{2})?$/.test(language.value.trim())) return 'enter a short language code such as en';
        const count = Number(maxResults.value);
        return Number.isInteger(count) && count >= 1 && count <= 20 ? null : 'maximum results must be between 1 and 20';
      },
    };
  };
  const filesBuilder = () => {
    fields.replaceChildren();
    const roots = namedRootsBuilder({
      noun: 'folder',
      pathHint: '/Users/you/Documents/project',
      helpText: 'The agent can list, search, and read matching text files under only these folders. Symlinks that escape a folder are refused. There are no create, edit, move, or delete tools.',
    });
    const extensions = el('input'); extensions.value = 'txt, md, json, jsonl, yaml, yml, csv, tsv, log, xml, html, toml';
    const maxKiB = el('input'); maxKiB.type = 'number'; maxKiB.min = '16'; maxKiB.max = '1024'; maxKiB.value = '256';
    const hidden = el('input'); hidden.type = 'checkbox'; hidden.style.width = 'auto';
    const hiddenLabel = el('label', null, ' include hidden files and folders (usually unsafe)'); hiddenLabel.prepend(hidden);
    fields.append(field('Allowed file extensions', extensions, 'Comma-separated, without dots.'), field('Maximum file size (KiB)', maxKiB, '16–1024 KiB'), hiddenLabel);
    const parsedExtensions = () => extensions.value.split(/[\s,]+/).map(x => x.trim().replace(/^\./, '').toLowerCase()).filter(Boolean);
    current = {
      caps: () => ({ roots: roots.values(), extensions: [...new Set(parsedExtensions())], max_bytes: Number(maxKiB.value) * 1024, include_hidden: hidden.checked }),
      validate: () => {
        if (!roots.valid()) return 'add at least one folder (name + path)';
        if (!parsedExtensions().length || parsedExtensions().some(x => !/^[a-z0-9][a-z0-9_-]*$/.test(x))) return 'add one or more simple file extensions';
        const size = Number(maxKiB.value);
        return Number.isFinite(size) && size >= 16 && size <= 1024 ? null : 'file limit must be between 16 and 1024 KiB';
      },
    };
  };
  const gitBuilder = () => {
    fields.replaceChildren();
    const repos = namedRootsBuilder({
      noun: 'repository',
      pathHint: '/Users/you/code/project',
      helpText: 'Read-only Git inspection: status, log, diff, show, and tracked-text search. Apiary invokes Git directly with hooks, external diff programs, pagers, and global configuration disabled.',
    });
    fields.append(help('Each selected folder must already be a Git repository. Working-tree changes can be read but never modified.'));
    current = {
      caps: () => ({ repos: repos.values() }),
      validate: () => repos.valid() ? null : 'add at least one repository (name + path)',
    };
  };
  const mcpBuilder = () => {
    fields.replaceChildren();
    const tr = el('select');
    for (const [v, t] of [['stdio', 'local program (stdio) — e.g. npx @modelcontextprotocol/server-filesystem'], ['http', 'remote server (HTTP) — URL, optionally OAuth']]) { const o = el('option', null, t); o.value = v; tr.append(o); }
    const access = accessSelect('read-only');
    const stdioBox = el('div');
    const cmd = el('input'); cmd.placeholder = 'command (npx, uvx, /path/to/server)';
    const args = el('input', 'grow'); args.placeholder = 'arguments, space-separated (-y @modelcontextprotocol/server-filesystem /Users/you/docs)';
    const envs = el('input'); envs.placeholder = 'env vars to pass through (optional, comma-separated)';
    const r1 = el('div', 'row'); r1.append(cmd, args); const r1b = el('div', 'row'); r1b.append(envs);
    stdioBox.append(r1, r1b, help('The program is spawned with a scrubbed environment (PATH, HOME, TMPDIR, LANG + what you list). Pre-run `npx …` once in a terminal so the first probe isn’t a download.'));
    const httpBox = el('div'); httpBox.style.display = 'none';
    const url = el('input', 'grow'); url.placeholder = 'https://mcp.example.com/mcp';
    const oauth = el('input'); oauth.placeholder = 'OAuth client id (if the server uses OAuth)';
    const bearer = el('input'); bearer.type = 'password'; bearer.placeholder = 'API key / bearer for discovery only (not stored)';
    const r2 = el('div', 'row'); r2.append(url); const r2b = el('div', 'row'); r2b.append(oauth, bearer);
    httpBox.append(r2, r2b, help('OAuth servers: leave the key blank; when you GRANT this to an agent the cockpit runs the sign-in and seals the tokens to that agent. Then use “Discover tools” on the agent’s Capabilities. API-key servers: the key is sealed at grant time; you can paste it here just to discover.'));
    const disc = el('button', 'btn', 'DISCOVER TOOLS');
    const dStatus = el('span', 'meta', '');
    const toolsBox = el('div');
    const dRow = el('div', 'row'); dRow.append(disc, dStatus);
    let picked = new Set();
    let known = [];
    const drawTools = () => {
      toolsBox.replaceChildren();
      if (!known.length) { toolsBox.append(help('Tools must be allowed by name. Discover the server first; in Read only mode, Apiary exposes only tools explicitly marked readOnlyHint=true.')); return; }
      const readOnly = access.value === 'read-only';
      const all = el('input'); all.type = 'checkbox'; all.style.width = 'auto';
      const al = el('label', null, readOnly ? ' allow every tool marked read only (*)' : ' allow every tool the server exposes (*)'); al.prepend(all);
      toolsBox.append(al, help('MCP access labels come from the server and are trust metadata, not a sandbox guarantee. Missing readOnlyHint is treated as write-capable.'));
      all.onchange = () => { if (all.checked) { picked = new Set(['*']); } else { picked.delete('*'); } drawTools(); };
      all.checked = picked.has('*');
      for (const t of known) {
        const unavailable = readOnly && !t.read_only;
        if (unavailable) picked.delete(t.name);
        const cb = el('input'); cb.type = 'checkbox'; cb.style.width = 'auto'; cb.disabled = unavailable; cb.checked = !unavailable && (picked.has('*') || picked.has(t.name));
        const risk = t.read_only ? 'read only' : 'may write';
        const lab = el('label', null, ` ${t.name} · ${risk}${t.description ? ' — ' + t.description.slice(0, 120) : ''}`); lab.prepend(cb);
        lab.style.display = 'block';
        cb.onchange = () => { picked.delete('*'); if (cb.checked) picked.add(t.name); else picked.delete(t.name); drawTools(); };
        toolsBox.append(lab);
      }
    };
    drawTools();
    tr.onchange = () => { stdioBox.style.display = tr.value === 'stdio' ? '' : 'none'; httpBox.style.display = tr.value === 'http' ? '' : 'none'; };
    access.onchange = drawTools;
    const trRow = el('div', 'row'); trRow.append(tr);
    fields.append(trRow, field('Access', access, 'Read only fails closed: unmarked tools are excluded. Read + write permits every tool you explicitly select.'), stdioBox, httpBox, dRow, toolsBox);
    const buildCaps = () => {
      const caps = { transport: tr.value, access: access.value, allowed_tools: [...picked] };
      if (tr.value === 'stdio') { caps.command = cmd.value.trim(); caps.args = args.value.trim() ? args.value.trim().split(/\s+/) : []; if (envs.value.trim()) caps.env = envs.value.split(',').map(x => x.trim()).filter(Boolean); }
      else { caps.url = url.value.trim(); if (oauth.value.trim()) caps.oauth_client_id = oauth.value.trim(); }
      return caps;
    };
    disc.onclick = async () => {
      dStatus.textContent = 'probing…';
      const caps = buildCaps();
      const r = await j('/api/connectors/discover', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ caps, bearer: bearer.value || undefined }) });
      if (r.ok) { known = r.tools || []; dStatus.textContent = `${known.length} tools`; drawTools(); }
      else if (r.auth_required) { dStatus.textContent = 'server wants OAuth — save the entry, grant it to an agent (that runs the sign-in), then discover from the agent’s Capabilities'; }
      else dStatus.textContent = 'failed: ' + r.error;
    };
    current = {
      caps: buildCaps,
      validate: () => {
        if (tr.value === 'stdio' && !cmd.value.trim()) return 'command required';
        if (tr.value === 'http' && !/^https?:\/\//.test(url.value.trim())) return 'a full URL is required';
        if (!picked.size) return 'allow at least one tool (Discover, then tick) — or * for all';
        if (access.value === 'read-only' && known.length && !known.some(t => t.read_only)) return 'this server marks no tools as read only; choose Read + write or use a server with readOnlyHint metadata';
        return null;
      },
    };
  };
  const nostrBuilder = () => {
    fields.replaceChildren();
    const relays = el('textarea', 'address-list'); relays.rows = 4;
    relays.placeholder = 'wss://nos.lol\nwss://relay.damus.io';
    relays.value = 'wss://nos.lol\nwss://relay.damus.io';
    const relayValues = () => relays.value.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
    fields.append(help('The agent may publish public notes (kind 1) signed with its own key — only to these relays. This is the allowlist; the agent cannot add relays.'),
      field('Relay addresses', relays, 'Enter one WebSocket address per line. Comma-separated paste also works.'));
    current = {
      caps: () => ({ relays: relayValues() }),
      validate: () => {
        const values = relayValues();
        if (!values.length) return 'add at least one relay address';
        return values.every(x => /^wss?:\/\//.test(x)) ? null : 'each relay must begin with wss:// or ws://';
      },
    };
  };
  const mockBuilder = () => { fields.replaceChildren(); fields.append(help('Echoes its input — for tests.')); current = { caps: () => ({}), validate: () => null }; };
  const pickBuilder = () => {
    nCaps.value = '';
    ({
      'web-search': webSearchBuilder,
      'web-fetch': webBuilder,
      'files': filesBuilder,
      'git': gitBuilder,
      'obsidian': () => vaultBuilder(true),
      'markdown-vault': () => vaultBuilder(false),
      'mcp': mcpBuilder,
      'nostr-publish': nostrBuilder,
    }[nKind.value] || mockBuilder)();
  };
  nKind.onchange = () => { selectedCatalogId = null; pickBuilder(); };
  pickBuilder();

  const saveLib = async () => {
    const r = await j('/api/connectors', {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ library: entries }),
    });
    lStatus.textContent = r.ok ? `saved (${r.count} entries)` : 'rejected: ' + r.error;
    if (r.ok) render();
    return r.ok;
  };
  const uniqueName = (base) => {
    const slug = base.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-|-$/g, '') || 'connector';
    if (!entries.some(e => e.name === slug)) return slug;
    let suffix = 2;
    while (entries.some(e => e.name === `${slug}-${suffix}`)) suffix++;
    return `${slug}-${suffix}`;
  };
  const drawCatalog = () => {
    catalogList.replaceChildren();
    for (const item of (lib.catalog || [])) {
      const card = el('article', 'catalog-item');
      card.append(el('h4', null, item.name), el('p', null, item.description));
      const meta = el('div', 'catalog-meta');
      meta.append(el('span', null, item.publisher), el('span', 'risk', item.risk));
      const row = el('div', 'row'); row.append(meta, el('span', 'grow', ''));
      const installed = entries.find(e => e.caps && e.caps.catalog_id === item.id);
      const directAdd = item.setup === 'credential' || item.setup === 'none';
      const action = el('button', 'btn', installed ? 'ADDED ✓' : (directAdd ? 'ADD TO LIBRARY' : 'CONFIGURE'));
      action.disabled = !!installed;
      row.append(action); card.append(row); catalogList.append(card);
      action.onclick = async () => {
        if (directAdd) {
          action.disabled = true; action.textContent = 'ADDING…';
          const caps = JSON.parse(JSON.stringify(item.caps || {})); caps.catalog_id = item.id;
          entries.push({ name: uniqueName(item.name), kind: item.kind, caps });
          window.__libFlash = item.setup === 'credential'
            ? `added ${item.name} — grant it from an agent’s Capabilities and seal the requested credential there`
            : `added ${item.name} — grant it to an agent, then ratify the capability change`;
          await saveLib();
          return;
        }
        selectedCatalogId = item.id;
        nKind.value = item.kind;
        nName.value = uniqueName(item.name);
        nName.dataset.auto = '1';
        pickBuilder();
        addSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
        fields.querySelector('input, textarea, select')?.focus();
      };
    }
  };
  drawList();
  drawCatalog();
  const flag = (elm, msg) => {
    lStatus.textContent = msg; lStatus.style.color = '#e07070';
    if (elm) { elm.style.outline = '2px solid #e07070'; elm.focus(); setTimeout(() => { elm.style.outline = ''; }, 2500); }
  };
  nGo.onclick = async () => {
    lStatus.style.color = '';
    let caps;
    if (nCaps.value.trim()) {
      try { caps = JSON.parse(nCaps.value); } catch { flag(nCaps, 'advanced caps is not valid JSON'); return; }
    } else {
      const bad = current.validate();
      if (bad) { flag(fields.querySelector('input, select'), bad); return; }
      caps = current.caps();
    }
    if (!nName.value.trim()) { flag(nName, 'name this library entry (top-left field) — e.g. the vault’s name'); return; }
    const name = nName.value.trim().replace(/[^A-Za-z0-9_-]/g, '-');
    if (entries.some(e => e.name === name)) { flag(nName, `“${name}” already exists in the library`); return; }
    if (selectedCatalogId) caps.catalog_id = selectedCatalogId;
    nGo.disabled = true; nGo.textContent = 'ADDING…';
    entries.push({ name, kind: nKind.value, caps });
    window.__libFlash = `added ${name} (${nKind.value}) — now GRANT it from an agent’s Capabilities, then ratify`;
    await saveLib();
    nGo.disabled = false; nGo.textContent = 'ADD TO LIBRARY';
  };

  const libRow = el('div', 'row');
  const libBtn = el('button', 'btn', 'OPEN HOST CONNECTOR LIBRARY');
  libBtn.onclick = () => { hostView = 'library'; render(); };
  libRow.append(libBtn, el('span', 'meta', 'definitions live host-side, shared by all agents — caps examples are in the library’s reference'));
  c.append(libRow);

  const docs = el('details');
  docs.append(el('summary', null, 'how connectors work'));
  const docsBody = el('div');
  docsBody.append(help('Two layers: the host library holds named configurations (kind + caps, never secrets); grants are per-agent and constitutional — they travel in the manifest, so portability includes capabilities and their sealed credentials. A destination host only needs to bind the kind; a declared kind it cannot bind fails loudly at run start.'));
  docsBody.append(help('The mcp kind speaks the Model Context Protocol (2026-07-28, automatic fallback to initialize-era servers). For OAuth-protected remote servers, grant an entry carrying oauth_client_id and the browser consent runs at grant time; for token servers, paste the bearer token as the secret. caps.allowed_tools is always required — the server offers whatever it likes, the manifest decides.'));
  docs.append(docsBody);
  c.append(docs);
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
  hostView = 'library';
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('sel'));
  render();
};
document.getElementById('foundtoggle').onclick = () => {
  hostView = 'found';
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('sel'));
  render();
};
document.getElementById('importtoggle').onclick = () => {
  hostView = 'import';
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('sel'));
  render();
};

// ------------------------------------------------------------ found (pane)

function renderFound(c) {
  if (!owners.length) {
    const setup = section('Create an approval identity',
      'Before creating another agent, add the human identity that will review its configuration and permissions.');
    const ownerName = el('input'); ownerName.placeholder = 'Your name';
    const ownerGo = el('button', 'btn solid', 'Create approval identity');
    const ownerSt = el('span', 'meta', '');
    const ownerRow = el('div', 'row'); ownerRow.append(ownerGo, ownerSt);
    setup.append(field('Local label', ownerName), ownerRow,
      help('This encrypted key is separate from every agent and is never shown as a runnable agent.'));
    c.append(setup);
    ownerGo.onclick = async () => {
      if (!ownerName.value.trim()) { ownerSt.textContent = 'Enter a name.'; ownerName.focus(); return; }
      ownerGo.disabled = true; ownerSt.textContent = 'Creating encrypted identity…';
      const r = await j('/api/owners', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: ownerName.value.trim() }) });
      ownerGo.disabled = false;
      if (!r.ok) { ownerSt.textContent = 'Could not create identity: ' + r.error; return; }
      await loadOwners(); render();
    };
    return;
  }
  const sec = section('Create a new agent',
    'Describe a clear job. Apiary creates a conservative configuration for you to review before anything can run.');
  const fName = el('input'); fName.placeholder = 'e.g. Research assistant';
  const fPurpose = el('textarea'); fPurpose.rows = 4; fPurpose.placeholder = 'What should this agent reliably help you do?';
  const fSuspend = el('select', 'grow');
  for (const identity of owners) {
    const option = el('option', null, identity.name || identity.npub.slice(0, 16));
    option.value = identity.npub; fSuspend.append(option);
  }
  if (!owners.length) {
    const option = el('option', null, 'No local approval identity'); option.value = ''; fSuspend.append(option);
  }
  const fDraft = el('input'); fDraft.type = 'checkbox'; fDraft.style.width = 'auto';
  fDraft.checked = !!hostStatus.anthropic_key_present;
  fDraft.disabled = !hostStatus.anthropic_key_present;
  const draftLabel = el('label', null, ' Tailor the draft with the connected model'); draftLabel.prepend(fDraft);
  const go = el('button', 'btn solid', 'Create draft');
  const st = el('span', 'meta', '');
  const r4 = el('div', 'row'); r4.append(draftLabel, go, st);
  sec.append(field('Agent name', fName), field('Purpose', fPurpose),
    field('Approved by', fSuspend, owners.length ? 'The agent cannot approve its own permissions.' : 'Create an approval identity during first-run setup or use the CLI for an external key.'),
    r4, help(hostStatus.anthropic_key_present
      ? 'The model can tailor routing and budgets to the purpose. You will review all changes before approval.'
      : 'No host model credential is configured, so Apiary will use its conservative template.'));
  c.append(sec);
  go.onclick = async () => {
    if (!fName.value.trim()) { st.textContent = 'Enter an agent name.'; fName.focus(); return; }
    if (!fPurpose.value.trim()) { st.textContent = 'Describe the agent’s purpose.'; fPurpose.focus(); return; }
    if (!fSuspend.value) { st.textContent = 'No approval identity is available on this host.'; fSuspend.focus(); return; }
    go.disabled = true; st.textContent = 'Creating the identity and draft configuration…';
    const r = await j('/api/agents/found', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: fName.value.trim(),
        purpose: fPurpose.value.trim(),
        suspend_keys: [fSuspend.value],
        draft_with: fDraft.checked ? 'anthropic' : null,
      }),
    });
    go.disabled = false;
    if (!r.ok) { st.textContent = 'Could not create the draft: ' + r.error; return; }
    st.textContent = `Draft created with ${r.drafted_by}.`;
    hostView = null; sel = r.npub; tab = 'manifest';
    document.querySelectorAll('nav button').forEach(x => x.classList.toggle('sel', x.dataset.tab === 'manifest'));
    await loadRoster(); render();
  };
}

// ------------------------------------------------------------ import (pane)

function renderImport(c) {
  const sec = section('Import an agent',
    'Choose an Apiary export bundle. Apiary verifies its identity, configuration, signatures, and history before saving anything. Imported agents arrive inactive.');
  const file = el('input'); file.type = 'file'; file.accept = '.json,.apiary.json,application/json';
  const bundle = el('textarea'); bundle.rows = 8; bundle.placeholder = 'paste .apiary.json bundle or sealed envelope';
  bundle.setAttribute('aria-label', 'Bundle JSON');
  const pass = el('input', 'grow'); pass.type = 'password';
  pass.placeholder = 'Only needed for a passphrase-protected handoff';
  const paste = el('details', 'technical'); paste.append(el('summary', null, 'Or paste bundle JSON'), bundle);
  const go = el('button', 'btn solid', 'Verify and import');
  const st = el('div', 'meta', '');
  const row = el('div', 'row'); row.append(pass, go);
  sec.append(field('Export bundle', file), paste, field('Handoff passphrase', pass), row, st,
    help('Sealed recipient bundles do not need a handoff passphrase. The imported private key is re-encrypted for this workspace.'));
  c.append(sec);
  file.onchange = async () => {
    const chosen = file.files && file.files[0];
    if (!chosen) return;
    try { bundle.value = await chosen.text(); st.textContent = `Loaded ${chosen.name}.`; }
    catch (err) { st.textContent = 'Could not read the file: ' + err; }
  };
  go.onclick = async () => {
    let parsed;
    try { parsed = JSON.parse(bundle.value); }
    catch { st.textContent = 'The selected bundle is not valid JSON.'; return; }
    go.disabled = true; st.textContent = 'Verifying identity, signatures, and history…';
    const r = await j('/api/agents/import', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ bundle: parsed, bundle_passphrase: pass.value || null }),
    });
    go.disabled = false;
    st.textContent = r.ok
      ? `Imported ${r.name || r.npub.slice(0, 12)} with ${r.log_entries} signed history entries. It is inactive on this host.`
      : 'Could not import: ' + r.error;
    if (r.ok) {
      bundle.value = ''; file.value = ''; hostView = null; sel = r.npub; tab = 'overview';
      await loadRoster(); openTab('overview');
    }
  };
}

loadStatus().then(loadOwners).then(loadRoster).then(render);
setInterval(loadStatus, 15000);
