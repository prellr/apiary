// Apiary cockpit. All dynamic strings render through textContent — agent
// names, log fields, model output, tool args, and errors are DATA, and the
// governance origin never interprets data as markup. (CSP backs this up:
// no inline script, no external sources.)
'use strict';

let sel = null, tab = 'run', agents = [];

async function j(url, opts) { const r = await fetch(url, opts); return r.json(); }

// el('div', 'cls', 'text') — safe node construction.
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

async function loadRoster() {
  const d = await j('/api/agents');
  agents = d.agents || [];
  const root = document.getElementById('roster');
  root.replaceChildren();
  if (!agents.length) root.append(el('div', 'empty', 'no agents in this keystore'));
  for (const a of agents) {
    const card = el('div', 'agent' + (sel === a.npub ? ' sel' : ''));
    const nm = el('div', 'nm', a.name || '(unnamed)');
    nm.append(el('span', 'badge ' + (a.ratified ? 'rat' : 'unrat'), a.ratified ? 'ratified' : 'unratified'));
    card.append(nm, el('div', 'np', a.npub), el('div', 'np', a.log_entries + ' log entries'));
    card.onclick = () => { sel = a.npub; render(); loadRoster(); };
    root.append(card);
  }
}

document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
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

async function render() {
  const c = document.getElementById('content');
  c.replaceChildren();
  if (!sel) { c.append(el('div', 'empty', 'select an agent')); return; }

  if (tab === 'manifest') {
    const d = await j(`/api/agents/${encodeURIComponent(sel)}/manifest`);
    if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }
    const status = d.ratified ? 'ratified' : 'NOT ratified — amend freely, then ratify';
    const head = entryLine('sha256', d.manifest_sha256 + ' — ' + status);
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
    c.append(head, ed, row);
    save.onclick = async () => {
      const r = await j(`/api/agents/${encodeURIComponent(sel)}/manifest`, {
        method: 'PUT', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ yaml: ed.value }),
      });
      status2.textContent = r.ok ? `saved · ${r.manifest_sha256.slice(0, 12)}… · re-ratify to run` : `rejected: ${r.error}`;
      loadRoster();
    };
    rat.onclick = async () => {
      if (!who.value || !who.value.startsWith('npub')) return;
      status2.textContent = 'ratifying…';
      const r = await j(`/api/agents/${encodeURIComponent(sel)}/ratify`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ as: who.value }),
      });
      status2.textContent = r.ok ? 'ratified ✓ both signatures in the log' : `refused: ${r.error}`;
      loadRoster(); if (r.ok) render();
    };
  } else if (tab === 'log') {
    const d = await j(`/api/agents/${encodeURIComponent(sel)}/log?tail=100`);
    if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }
    const chain = d.chain.valid ? `chain valid · ${d.chain.entries} entries` : `CHAIN BROKEN: ${d.chain.error}`;
    c.append(entryLine('signed log', chain));
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
  } else {
    const box = el('div'); box.id = 'runbox';
    const ta = el('textarea'); ta.id = 'task'; ta.placeholder = 'task for this agent…';
    const go = el('button', null, 'RUN'); go.id = 'go';
    box.append(ta, go);
    const events = el('div'); events.id = 'events';
    c.append(box, events);
    go.onclick = () => runTask(ta, go, events);
  }
}

function ev(events, cls, text) {
  events.prepend(el('div', 'ev ' + cls, text));
}

async function runTask(ta, go, events) {
  const task = ta.value.trim();
  if (!task) return;
  go.disabled = true;
  events.replaceChildren();
  try {
    const resp = await fetch(`/api/agents/${encodeURIComponent(sel)}/run`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ task }),
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

document.getElementById('foundtoggle').onclick = () => {
  const f = document.getElementById('foundform');
  f.style.display = f.style.display === 'block' ? 'none' : 'block';
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

loadRoster();
