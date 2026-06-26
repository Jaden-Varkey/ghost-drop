// view.js — recipient flow: poison check, consume one view, decrypt locally.

(function () {
  const statusEl = document.getElementById('status');
  const revealCard = document.getElementById('reveal-card');
  const revealBtn = document.getElementById('reveal-btn');
  const metaEl = document.getElementById('meta');
  const secretCard = document.getElementById('secret-card');
  const secretOut = document.getElementById('secret-out');
  const copyBtn = document.getElementById('copy-secret-btn');
  const remainingEl = document.getElementById('remaining');
  const blockedCard = document.getElementById('blocked-card');
  const blockedMsg = document.getElementById('blocked-msg');

  // /view/:id  +  #<key>
  const parts = window.location.pathname.split('/').filter(Boolean);
  const secretId = parts[parts.length - 1];
  const keyB64url = window.location.hash.replace(/^#/, '');

  function show(el) {
    el.hidden = false;
  }
  function hide(el) {
    el.hidden = true;
  }

  function blocked(title, msg) {
    hide(statusEl);
    hide(revealCard);
    hide(secretCard);
    blockedMsg.textContent = msg;
    document.getElementById('blocked-title').textContent = title;
    show(blockedCard);
  }

  async function init() {
    if (!secretId || !keyB64url) {
      blocked(
        'Invalid link',
        'This link is missing its decryption key or id. Make sure you copied the entire URL, including everything after the # symbol.'
      );
      return;
    }

    // 1) POISON CHECK — before any network call. If this device already viewed
    //    the secret, we refuse to fire the API at all.
    const poison = await window.GhostPoison.getPoison(secretId);
    if (poison) {
      blocked(
        'Already viewed on this device',
        'You have already opened this secret on this device. Each device may only view it once — refreshing will not grant another view.'
      );
      return;
    }

    // 2) Non-destructive status so the user makes a deliberate choice before
    //    burning a view.
    try {
      const res = await fetch(
        `/api/secrets/${encodeURIComponent(secretId)}/meta`
      );
      if (res.status === 404) {
        blocked(
          'Gone',
          'This secret no longer exists. It has either reached its view limit or expired, and has been permanently destroyed.'
        );
        return;
      }
      const meta = await res.json();
      metaEl.textContent =
        `${meta.remaining} view${meta.remaining === 1 ? '' : 's'} remaining` +
        (meta.expiresAt
          ? ` · expires ${new Date(meta.expiresAt).toLocaleString()}`
          : '');
      hide(statusEl);
      show(revealCard);
    } catch {
      blocked('Error', 'Could not reach the server. Please try again.');
    }
  }

  revealBtn.addEventListener('click', async () => {
    revealBtn.disabled = true;
    revealBtn.textContent = 'Revealing…';

    // Re-check poison right before firing — defends against two tabs racing.
    const poison = await window.GhostPoison.getPoison(secretId);
    if (poison) {
      blocked(
        'Already viewed on this device',
        'You have already opened this secret on this device.'
      );
      return;
    }

    try {
      const res = await fetch(
        `/api/secrets/${encodeURIComponent(secretId)}/view`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' } }
      );

      if (res.status === 410) {
        blocked(
          'Gone',
          'This secret reached its view limit or expired just now and has been permanently destroyed.'
        );
        return;
      }
      if (res.status === 403) {
        blocked(
          'Already viewed on this device',
          'The server has on record that this device already viewed this secret.'
        );
        return;
      }
      if (!res.ok) {
        throw new Error(`Request failed (${res.status})`);
      }

      const { ciphertext, iv, remaining, poison: token } = await res.json();

      // 3) POISON this device immediately — before decrypting/displaying — so a
      //    crash mid-render still counts the view as spent on this device.
      await window.GhostPoison.setPoison(secretId, token);

      // 4) Decrypt locally with the key from the URL hash.
      const plaintext = await window.GhostCrypto.decryptSecret({
        ciphertext,
        iv,
        keyB64url,
      });

      secretOut.value = plaintext;
      remainingEl.textContent =
        remaining > 0
          ? `${remaining} view${remaining === 1 ? '' : 's'} remaining for others.`
          : 'That was the last view — this secret has now been permanently destroyed.';

      hide(revealCard);
      show(secretCard);
    } catch (err) {
      blocked(
        'Error',
        (err && err.message) ||
          'Decryption or retrieval failed. The link may be corrupted.'
      );
    }
  });

  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(secretOut.value);
      copyBtn.textContent = 'Copied!';
      setTimeout(() => (copyBtn.textContent = 'Copy'), 1500);
    } catch {
      secretOut.select();
      document.execCommand('copy');
    }
  });

  init();
})();
