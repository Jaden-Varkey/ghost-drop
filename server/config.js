'use strict';

const crypto = require('crypto');

require('dotenv').config();

function bool(value, fallback) {
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function int(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

// A JWT secret is required to mint/verify the device-poison tokens. If the
// operator doesn't supply one we generate an ephemeral secret so the app still
// runs out-of-the-box, but we warn loudly because restarts will then
// invalidate previously issued poison tokens.
let jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  jwtSecret = crypto.randomBytes(32).toString('hex');
  // eslint-disable-next-line no-console
  console.warn(
    '[config] JWT_SECRET not set — generated an ephemeral one. ' +
      'Set JWT_SECRET in your environment for stable poison tokens.'
  );
}

const config = {
  port: int(process.env.PORT, 3000),
  host: process.env.HOST || '0.0.0.0',

  // Which backing store to use: "redis" | "memory" | "auto".
  // "auto" tries Redis and transparently falls back to memory if it can't
  // connect, which keeps local development zero-setup.
  storeDriver: (process.env.STORE_DRIVER || 'auto').toLowerCase(),
  redisUrl: process.env.REDIS_URL || 'redis://127.0.0.1:6379',

  jwtSecret,

  // Guard rails on what a sender can request.
  maxCiphertextBytes: int(process.env.MAX_CIPHERTEXT_BYTES, 64 * 1024), // 64 KiB of ciphertext
  maxViewLimit: int(process.env.MAX_VIEW_LIMIT, 100),
  maxTtlSeconds: int(process.env.MAX_TTL_SECONDS, 30 * 24 * 60 * 60), // 30 days
  minTtlSeconds: int(process.env.MIN_TTL_SECONDS, 60), // 1 minute

  trustProxy: bool(process.env.TRUST_PROXY, false),
};

module.exports = config;
