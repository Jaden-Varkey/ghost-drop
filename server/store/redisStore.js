'use strict';

const Redis = require('ioredis');

const BLOB_PREFIX = 'ghostdrop:blob:';
const TOKENS_PREFIX = 'ghostdrop:tokens:';

// Atomic "dispense a ticket" operation. Popping the token, checking how many
// remain, and destroying the blob on the final view all happen inside one Lua
// script so two simultaneous viewers can never both grab the same token or
// race past the view limit.
//
// KEYS[1] = tokens list key
// KEYS[2] = blob key
// Returns: { 'gone' } | { 'ok', <blobJson>, <remainingAsString> }
const CONSUME_SCRIPT = `
local token = redis.call('LPOP', KEYS[1])
if not token then
  redis.call('DEL', KEYS[1])
  redis.call('DEL', KEYS[2])
  return {'gone'}
end
local blob = redis.call('GET', KEYS[2])
if not blob then
  redis.call('DEL', KEYS[1])
  return {'gone'}
end
local remaining = redis.call('LLEN', KEYS[1])
if remaining == 0 then
  redis.call('DEL', KEYS[1])
  redis.call('DEL', KEYS[2])
end
return {'ok', blob, tostring(remaining)}
`;

/**
 * Redis-backed implementation of the GhostDrop store.
 */
class RedisStore {
  /** @param {import('ioredis').Redis} client */
  constructor(client) {
    this.client = client;
    this.client.defineCommand('ghostConsume', {
      numberOfKeys: 2,
      lua: CONSUME_SCRIPT,
    });
  }

  /**
   * Connect to Redis, failing fast if the server is unreachable. Returns a
   * ready RedisStore.
   */
  static async connect(redisUrl) {
    const client = new Redis(redisUrl, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      // Don't let ioredis retry forever during startup probing.
      retryStrategy: () => null,
    });
    // Surface connection errors instead of crashing the process later.
    client.on('error', () => {});
    await client.connect();
    await client.ping();
    return new RedisStore(client);
  }

  _blobKey(id) {
    return BLOB_PREFIX + id;
  }

  _tokensKey(id) {
    return TOKENS_PREFIX + id;
  }

  async createSecret({ id, ciphertext, iv, tokens, ttlSeconds }) {
    const blobKey = this._blobKey(id);
    const tokensKey = this._tokensKey(id);
    const blob = JSON.stringify({ ciphertext, iv });

    const pipe = this.client.multi();
    pipe.set(blobKey, blob, 'EX', ttlSeconds);
    pipe.rpush(tokensKey, ...tokens);
    pipe.expire(tokensKey, ttlSeconds);
    await pipe.exec();
  }

  async getMeta(id) {
    const blobKey = this._blobKey(id);
    const tokensKey = this._tokensKey(id);

    const pipe = this.client.multi();
    pipe.exists(blobKey);
    pipe.llen(tokensKey);
    pipe.pttl(blobKey);
    const results = await pipe.exec();

    const exists = results[0][1] === 1;
    if (!exists) return null;

    const remaining = results[1][1];
    const pttl = results[2][1];
    return {
      exists: true,
      remaining,
      expiresAt: pttl > 0 ? Date.now() + pttl : null,
    };
  }

  async consumeView(id) {
    const res = await this.client.ghostConsume(
      this._tokensKey(id),
      this._blobKey(id)
    );

    if (!res || res[0] === 'gone') {
      return { status: 'gone' };
    }

    const blob = JSON.parse(res[1]);
    const remaining = parseInt(res[2], 10);
    return {
      status: 'ok',
      ciphertext: blob.ciphertext,
      iv: blob.iv,
      remaining,
    };
  }

  async close() {
    await this.client.quit();
  }
}

module.exports = RedisStore;
