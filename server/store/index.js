'use strict';

const config = require('../config');
const MemoryStore = require('./memoryStore');
const RedisStore = require('./redisStore');

/**
 * Build the store described by config.storeDriver.
 *
 *   redis  -> Redis required; throw if unreachable.
 *   memory -> always in-memory.
 *   auto   -> try Redis, fall back to memory (default, zero-setup friendly).
 */
async function createStore(log = console) {
  const driver = config.storeDriver;

  if (driver === 'memory') {
    log.info('[store] using in-memory store (STORE_DRIVER=memory)');
    return new MemoryStore();
  }

  if (driver === 'redis') {
    const store = await RedisStore.connect(config.redisUrl);
    log.info(`[store] using Redis store at ${config.redisUrl}`);
    return store;
  }

  // auto
  try {
    const store = await RedisStore.connect(config.redisUrl);
    log.info(`[store] using Redis store at ${config.redisUrl}`);
    return store;
  } catch (err) {
    log.warn(
      `[store] Redis unavailable (${err.message}); falling back to in-memory ` +
        'store. Data will not survive a restart and will not be shared across ' +
        'instances. Set STORE_DRIVER=redis to require Redis.'
    );
    return new MemoryStore();
  }
}

module.exports = { createStore };
