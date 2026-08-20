'use strict';

const button = document.getElementById('signin');
const status = document.getElementById('status');

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
  location.replace('/');
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
