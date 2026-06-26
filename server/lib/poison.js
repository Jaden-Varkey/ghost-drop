'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');

const ISSUER = 'ghostdrop';

/**
 * Mint a signed "poison" token that marks a device as having already viewed a
 * given secret. The client stores this in LocalStorage *and* IndexedDB and
 * replays it on future attempts; the server also verifies it as server-side
 * authority so a cleared-storage refresh still can't double-dip while a token
 * survives.
 *
 * @param {string} secretId
 * @param {number} ttlSeconds - poison lives at least as long as the secret could.
 */
function mintPoison(secretId, ttlSeconds) {
  return jwt.sign({ sid: secretId }, config.jwtSecret, {
    issuer: ISSUER,
    subject: 'poison',
    expiresIn: Math.max(60, ttlSeconds),
  });
}

/**
 * Verify a poison token and confirm it belongs to the given secret id.
 * @returns {boolean} true if the token is a valid poison for this secret.
 */
function isPoisonedFor(token, secretId) {
  if (!token) return false;
  try {
    const payload = jwt.verify(token, config.jwtSecret, {
      issuer: ISSUER,
      subject: 'poison',
    });
    return payload.sid === secretId;
  } catch {
    return false;
  }
}

module.exports = { mintPoison, isPoisonedFor };
