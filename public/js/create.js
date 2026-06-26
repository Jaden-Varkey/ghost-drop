// create.js — sender flow: encrypt locally, store ciphertext, get a share link.

(function () {
  const form = document.getElementById('create-form');
  const secretEl = document.getElementById('secret');
  const viewLimitEl = document.getElementById('view-limit');
  const expiryEl = document.getElementById('expiry');
  const submitBtn = document.getElementById('submit-btn');
  const errorEl = document.getElementById('error');
  const resultEl = document.getElementById('result');
  const linkEl = document.getElementById('share-link');
  const copyBtn = document.getElementById('copy-btn');
  const summaryEl = document.getElementById('summary');
  const againBtn = document.getElementById('again-btn');

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.hidden = false;
  }

  function clearError() {
    errorEl.hidden = true;
    errorEl.textContent = '';
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearError();

    const plaintext = secretEl.value;
    if (!plaintext) {
      showError('Enter a secret to share.');
      return;
    }

    const viewLimit = parseInt(viewLimitEl.value, 10);
    if (!Number.isInteger(viewLimit) || viewLimit < 1) {
      showError('View limit must be at least 1.');
      return;
    }

    const ttlSeconds = parseInt(expiryEl.value, 10);

    submitBtn.disabled = true;
    submitBtn.textContent = 'Encrypting…';

    try {
      // 1) Encrypt entirely in the browser.
      const { ciphertext, iv, keyB64url } =
        await window.GhostCrypto.encryptSecret(plaintext);

      // 2) Store only the ciphertext server-side.
      const res = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ciphertext, iv, viewLimit, ttlSeconds }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `Request failed (${res.status})`);
      }

      const { id } = await res.json();

      // 3) Build the share link with the key in the hash (never sent to server).
      const url = `${window.location.origin}/view/${id}#${keyB64url}`;
      linkEl.value = url;

      const expLabel = expiryEl.options[expiryEl.selectedIndex].text;
      summaryEl.textContent =
        `${viewLimit} view${viewLimit === 1 ? '' : 's'} · expires in ${expLabel}`;

      // Wipe the plaintext from the page.
      secretEl.value = '';
      form.hidden = true;
      resultEl.hidden = false;
    } catch (err) {
      showError(err.message || 'Something went wrong.');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create secure link';
    }
  });

  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(linkEl.value);
      copyBtn.textContent = 'Copied!';
      setTimeout(() => (copyBtn.textContent = 'Copy'), 1500);
    } catch {
      linkEl.select();
      document.execCommand('copy');
    }
  });

  againBtn.addEventListener('click', () => {
    resultEl.hidden = true;
    form.hidden = false;
    linkEl.value = '';
  });
})();
