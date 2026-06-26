'use strict';

const crypto = require('crypto');
const express = require('express');
const config = require('../config');
const { mintPoison, isPoisonedFor } = require('../lib/poison');

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const ID_RE = /^[A-Za-z0-9_-]{10,64}$/;

function isBase64(str, maxBytes) {
  if (typeof str !== 'string' || str.length === 0) return false;
  if (!BASE64_RE.test(str)) return false;
  // Rough decoded-size guard without allocating the full buffer twice.
  const approxBytes = Math.floor((str.length * 3) / 4);
  if (maxBytes && approxBytes > maxBytes) return false;
  return true;
}

function bearerFrom(req) {
  const header = req.get('authorization') || '';
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1] : null;
}

/**
 * @param {{createSecret:Function, getMeta:Function, consumeView:Function}} store
 */
function createSecretsRouter(store) {
  const router = express.Router();

  // --- Create a secret -----------------------------------------------------
  // Body: { ciphertext (b64), iv (b64), viewLimit (int), ttlSeconds (int) }
  // The plaintext and key never reach here — only the AES-GCM ciphertext.
  router.post('/', async (req, res) => {
    const { ciphertext, iv, viewLimit, ttlSeconds } = req.body || {};

    if (!isBase64(ciphertext, config.maxCiphertextBytes)) {
      return res.status(400).json({ error: 'invalid_ciphertext' });
    }
    if (!isBase64(iv, 64)) {
      return res.status(400).json({ error: 'invalid_iv' });
    }

    const views = Number(viewLimit);
    if (!Number.isInteger(views) || views < 1 || views > config.maxViewLimit) {
      return res
        .status(400)
        .json({ error: 'invalid_view_limit', max: config.maxViewLimit });
    }

    const ttl = Number(ttlSeconds);
    if (
      !Number.isInteger(ttl) ||
      ttl < config.minTtlSeconds ||
      ttl > config.maxTtlSeconds
    ) {
      return res.status(400).json({
        error: 'invalid_ttl',
        min: config.minTtlSeconds,
        max: config.maxTtlSeconds,
      });
    }

    // Unguessable id; tokens are opaque single-use markers.
    const id = crypto.randomBytes(16).toString('base64url');
    const tokens = Array.from({ length: views }, () =>
      crypto.randomBytes(12).toString('base64url')
    );

    await store.createSecret({ id, ciphertext, iv, tokens, ttlSeconds: ttl });

    return res.status(201).json({ id, viewLimit: views, ttlSeconds: ttl });
  });

  // --- Non-destructive metadata -------------------------------------------
  // Lets the view page show "exists / N views left / expires" without burning
  // a token. Returns 404 once the secret is gone.
  router.get('/:id/meta', async (req, res) => {
    const { id } = req.params;
    if (!ID_RE.test(id)) return res.status(404).json({ error: 'not_found' });

    const meta = await store.getMeta(id);
    if (!meta) return res.status(404).json({ error: 'not_found' });

    return res.json({
      exists: true,
      remaining: meta.remaining,
      expiresAt: meta.expiresAt,
    });
  });

  // --- Consume a view (destructive) ---------------------------------------
  // Server-side authority: if the caller presents a valid poison token for
  // this secret, reject *without* burning a view. Otherwise pop one token,
  // return the ciphertext, and hand back a freshly minted poison token for the
  // client to persist.
  router.post('/:id/view', async (req, res) => {
    const { id } = req.params;
    if (!ID_RE.test(id)) return res.status(404).json({ error: 'not_found' });

    const presented = bearerFrom(req);
    if (isPoisonedFor(presented, id)) {
      return res.status(403).json({ error: 'already_viewed' });
    }

    const result = await store.consumeView(id);
    if (result.status === 'gone') {
      return res.status(410).json({ error: 'gone' });
    }

    // Poison should outlive the (now possibly shorter) remaining window; tie it
    // to the max TTL so a refresh can't beat an expiring poison token.
    const poison = mintPoison(id, config.maxTtlSeconds);

    return res.json({
      ciphertext: result.ciphertext,
      iv: result.iv,
      remaining: result.remaining,
      poison,
    });
  });

  return router;
}

module.exports = { createSecretsRouter };
