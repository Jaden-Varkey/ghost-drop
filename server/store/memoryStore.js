'use strict';

/**
 * In-memory implementation of the GhostDrop store.
 *
 * Mirrors the exact semantics of the Redis store so the two are
 * interchangeable: a blob plus a "list" of single-use tokens, both expiring at
 * the same wall-clock deadline. Node runs our request handlers on a single
 * thread, so the read-modify-write in `consumeView` is effectively atomic
 * without extra locking.
 */
class MemoryStore {
  constructor() {
    /** @type {Map<string, {blob: {ciphertext:string, iv:string}, tokens: string[], expiresAt: number}>} */
    this.records = new Map();

    // Periodically evict expired records. unref() so the timer never keeps the
    // process alive on its own.
    this._sweeper = setInterval(() => this._sweep(), 30 * 1000);
    if (typeof this._sweeper.unref === 'function') this._sweeper.unref();
  }

  _sweep() {
    const now = Date.now();
    for (const [id, rec] of this.records) {
      if (rec.expiresAt <= now) this.records.delete(id);
    }
  }

  _live(id) {
    const rec = this.records.get(id);
    if (!rec) return null;
    if (rec.expiresAt <= Date.now()) {
      this.records.delete(id);
      return null;
    }
    return rec;
  }

  async createSecret({ id, ciphertext, iv, tokens, ttlSeconds }) {
    this.records.set(id, {
      blob: { ciphertext, iv },
      tokens: [...tokens],
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }

  async getMeta(id) {
    const rec = this._live(id);
    if (!rec) return null;
    return {
      exists: true,
      remaining: rec.tokens.length,
      expiresAt: rec.expiresAt,
    };
  }

  /**
   * Pop a single token and, if it was the last one, destroy the blob.
   * @returns {Promise<{status:'ok', ciphertext:string, iv:string, remaining:number} | {status:'gone'}>}
   */
  async consumeView(id) {
    const rec = this._live(id);
    if (!rec || rec.tokens.length === 0) {
      // No tokens left (or never existed): make sure nothing lingers.
      this.records.delete(id);
      return { status: 'gone' };
    }

    rec.tokens.shift(); // burn one single-use token
    const remaining = rec.tokens.length;
    const { ciphertext, iv } = rec.blob;

    if (remaining === 0) {
      // Final destruction — the blob is wiped the instant the last view lands.
      this.records.delete(id);
    }

    return { status: 'ok', ciphertext, iv, remaining };
  }

  async close() {
    clearInterval(this._sweeper);
    this.records.clear();
  }
}

module.exports = MemoryStore;
