// crypto.js — client-side zero-knowledge encryption helpers (WebCrypto).
//
// The AES-GCM key is generated in the browser, used to encrypt the secret, and
// exported into the URL hash. It is NEVER sent to the server. The server only
// ever stores opaque ciphertext + iv.

const enc = new TextEncoder();
const dec = new TextDecoder();

// --- base64url helpers (URL-hash safe) ---------------------------------------
function bytesToB64url(bytes) {
  let bin = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Standard base64 (what the API expects for ciphertext/iv).
function bytesToB64(bytes) {
  let bin = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/**
 * Encrypt a UTF-8 string. Returns { ciphertext, iv } (both base64) plus the
 * raw key encoded as base64url for the URL hash.
 */
async function encryptSecret(plaintext) {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ctBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(plaintext)
  );
  const rawKey = await crypto.subtle.exportKey('raw', key);
  return {
    ciphertext: bytesToB64(ctBuf),
    iv: bytesToB64(iv),
    keyB64url: bytesToB64url(rawKey),
  };
}

/**
 * Decrypt with a key recovered from the URL hash.
 * @returns {Promise<string>} the plaintext
 */
async function decryptSecret({ ciphertext, iv, keyB64url }) {
  const key = await crypto.subtle.importKey(
    'raw',
    b64urlToBytes(keyB64url),
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
  const ptBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(iv) },
    key,
    b64ToBytes(ciphertext)
  );
  return dec.decode(ptBuf);
}

window.GhostCrypto = { encryptSecret, decryptSecret };
