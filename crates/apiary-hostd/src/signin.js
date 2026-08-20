'use strict';

const button = document.getElementById('signin');
const status = document.getElementById('status');
const workspaceSwitcher = document.getElementById('workspace-switcher');
const workspace = document.getElementById('workspace');
const switchWorkspace = document.getElementById('switch-workspace');
const workspaceStatus = document.getElementById('workspace-status');
const desktopAuth = document.getElementById('desktop-auth');
const desktopManager = document.getElementById('desktop-manager');
const desktopContinue = document.getElementById('desktop-continue');

function desktopBootstrap() {
  const prefix = '#desktop=';
  if (!location.hash.startsWith(prefix)) return null;
  try {
    return JSON.parse(decodeURIComponent(location.hash.slice(prefix.length)));
  } catch (_) {
    return null;
  }
}

const DESKTOP = desktopBootstrap();

function desktopHash() {
  if (!DESKTOP) return location.hash;
  const safe = { ...DESKTOP };
  delete safe.access_token;
  return '#desktop=' + encodeURIComponent(JSON.stringify(safe));
}

function desktopAction(action, params) {
  const target = new URL(`apiary-desktop://${action}`);
  for (const [key, value] of Object.entries(params || {})) {
    target.searchParams.set(key, String(value));
  }
  location.assign(target.href);
}

function renderWorkspaceSwitcher() {
  const desktop = DESKTOP;
  if (!desktop || desktop.environment_override) return;

  const current = desktop.mode === 'remote' ? desktop.active_remote : 'local';
  const local = document.createElement('option');
  local.value = 'local';
  local.textContent = 'This Mac (local)';
  workspace.append(local);
  for (const profile of Array.isArray(desktop.remotes) ? desktop.remotes : []) {
    const option = document.createElement('option');
    option.value = profile.id;
    option.textContent = `${profile.name} (${profile.ssh_target})`;
    workspace.append(option);
  }
  workspace.value = current || 'local';
  switchWorkspace.disabled = workspace.value === current;
  workspace.addEventListener('change', () => {
    switchWorkspace.disabled = workspace.value === current;
  });
  switchWorkspace.addEventListener('click', () => {
    switchWorkspace.disabled = true;
    workspaceStatus.textContent = 'Confirm the workspace change in the Apiary dialog.';
    desktopAction('switch', { profile: workspace.value });
  });
  workspaceSwitcher.hidden = false;
}

async function desktopSignIn(manager) {
  if (!DESKTOP || !DESKTOP.access_token) return false;
  status.className = '';
  status.textContent = 'Authenticating through your SSH connection…';
  const response = await fetch('/api/desktop/session', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      authorization: 'Bearer ' + DESKTOP.access_token,
      'content-type': 'application/json',
    },
    body: JSON.stringify(manager ? { manager } : {}),
  });
  const result = await response.json().catch(() => ({}));
  if (response.status === 409 && Array.isArray(result.managers)) {
    desktopManager.replaceChildren();
    for (const approved of result.managers) {
      const option = document.createElement('option');
      option.value = approved.npub;
      option.textContent = `${approved.name} (${approved.npub.slice(0, 12)}…${approved.npub.slice(-6)})`;
      desktopManager.append(option);
    }
    desktopAuth.hidden = false;
    status.textContent = 'Choose the approved manager identity for this SSH connection.';
    return false;
  }
  if (!response.ok || !result.ok) {
    throw new Error(result.error || `Desktop authentication was refused (${response.status}).`);
  }
  sessionStorage.setItem('apiary.csrf', result.csrf);
  sessionStorage.setItem('apiary.npub', result.npub);
  location.replace('/' + desktopHash());
  return true;
}

async function beginDesktopSignIn(manager) {
  desktopContinue.disabled = true;
  try {
    await desktopSignIn(manager);
  } catch (error) {
    status.className = 'bad';
    status.textContent = error && error.message
      ? error.message
      : 'Could not authenticate this desktop connection.';
    desktopAuth.hidden = false;
  } finally {
    desktopContinue.disabled = false;
  }
}

function bytesBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

async function signIn() {
  status.className = '';
  if (!window.nostr || typeof window.nostr.signEvent !== 'function') {
    throw new Error('Enable a NIP-07 Nostr signer in this browser, then try again.');
  }
  const target = new URL('/api/session', location.href);
  const signed = await window.nostr.signEvent({
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['u', target.href], ['method', 'POST']],
    content: '',
  });
  const authorization = 'Nostr ' + bytesBase64(
    new TextEncoder().encode(JSON.stringify(signed)),
  );
  const response = await fetch('/api/session', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { authorization },
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.ok) {
    if (response.status === 403) {
      throw new Error('This Nostr identity has not been granted access to this Apiary host.');
    }
    throw new Error(result.error || `Sign-in was refused (${response.status}).`);
  }
  sessionStorage.setItem('apiary.csrf', result.csrf);
  sessionStorage.setItem('apiary.npub', result.npub);
  // Preserve the desktop-only bootstrap fragment. The server never receives
  // it, but the authenticated cockpit needs it to render the same switcher.
  location.replace('/' + desktopHash());
}

button.addEventListener('click', async () => {
  button.disabled = true;
  status.textContent = 'Waiting for your Nostr signer…';
  try {
    await signIn();
  } catch (error) {
    status.className = 'bad';
    status.textContent = error && error.message ? error.message : 'Could not sign in.';
    button.disabled = false;
  }
});

desktopContinue.addEventListener('click', () => {
  beginDesktopSignIn(desktopManager.value || undefined);
});

renderWorkspaceSwitcher();
if (DESKTOP && DESKTOP.access_token) {
  button.hidden = true;
  beginDesktopSignIn();
}
