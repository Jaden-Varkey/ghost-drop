// poison.js — device-side "poison" persistence.
//
// After a successful view we write a server-signed JWT into BOTH LocalStorage
// and IndexedDB, keyed by the secret id. On any later visit we aggressively
// check both stores; if either holds a poison token we refuse to even fire the
// API call. Using two independent stores makes a casual "clear one of them"
// refresh insufficient to earn another view.

const LS_PREFIX = 'ghostdrop:poison:';
const IDB_NAME = 'ghostdrop';
const IDB_STORE = 'poison';

function lsKey(secretId) {
  return LS_PREFIX + secretId;
}

// --- IndexedDB (promise-wrapped) ---------------------------------------------
function openIdb() {
  return new Promise((resolve, reject) => {
    let req;
    try {
      req = indexedDB.open(IDB_NAME, 1);
    } catch (e) {
      return reject(e);
    }
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(secretId) {
  try {
    const db = await openIdb();
    return await new Promise((resolve) => {
      const tx = db.transaction(IDB_STORE, 'readonly');
      const req = tx.objectStore(IDB_STORE).get(secretId);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => resolve(null);
    });
  } catch {
    return null; // IndexedDB unavailable (e.g. private mode) — fail open to LS.
  }
}

async function idbSet(secretId, token) {
  try {
    const db = await openIdb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).put(token, secretId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    /* best effort */
  }
}

// --- LocalStorage ------------------------------------------------------------
function lsGet(secretId) {
  try {
    return localStorage.getItem(lsKey(secretId));
  } catch {
    return null;
  }
}

function lsSet(secretId, token) {
  try {
    localStorage.setItem(lsKey(secretId), token);
  } catch {
    /* best effort */
  }
}

/**
 * @returns {Promise<string|null>} a stored poison token from either store, if any.
 */
async function getPoison(secretId) {
  const fromLs = lsGet(secretId);
  if (fromLs) return fromLs;
  const fromIdb = await idbGet(secretId);
  return fromIdb || null;
}

/** Persist the poison token in both stores. */
async function setPoison(secretId, token) {
  lsSet(secretId, token);
  await idbSet(secretId, token);
}

window.GhostPoison = { getPoison, setPoison };
