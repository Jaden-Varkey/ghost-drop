'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const express = require('express');

const MemoryStore = require('../server/store/memoryStore');
const { createSecretsRouter } = require('../server/routes/secrets');

// Spin up a throwaway server backed by an in-memory store.
function makeServer() {
  const store = new MemoryStore();
  const app = express();
  app.use(express.json());
  app.use('/api/secrets', createSecretsRouter(store));
  const server = http.createServer(app);
  return { server, store };
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

async function req(port, method, path, { body, auth } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth) headers.Authorization = `Bearer ${auth}`;
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

const sample = { ciphertext: 'aGVsbG8=', iv: 'MTIzNDU2Nzg5MDEy' };

test('create → multi-view → final destruction', async (t) => {
  const { server } = makeServer();
  const port = await listen(server);
  t.after(() => server.close());

  // Create with a limit of 2 views.
  const created = await req(port, 'POST', '/api/secrets', {
    body: { ...sample, viewLimit: 2, ttlSeconds: 3600 },
  });
  assert.strictEqual(created.status, 201);
  const { id } = created.json;
  assert.ok(id);

  // Meta is non-destructive: still 2 remaining.
  let meta = await req(port, 'GET', `/api/secrets/${id}/meta`);
  assert.strictEqual(meta.status, 200);
  assert.strictEqual(meta.json.remaining, 2);

  // First view: 1 remaining, returns blob + poison token.
  const v1 = await req(port, 'POST', `/api/secrets/${id}/view`);
  assert.strictEqual(v1.status, 200);
  assert.strictEqual(v1.json.remaining, 1);
  assert.strictEqual(v1.json.ciphertext, sample.ciphertext);
  assert.ok(v1.json.poison);

  // Second (final) view: 0 remaining.
  const v2 = await req(port, 'POST', `/api/secrets/${id}/view`);
  assert.strictEqual(v2.status, 200);
  assert.strictEqual(v2.json.remaining, 0);

  // Now destroyed: meta 404, further views 410.
  meta = await req(port, 'GET', `/api/secrets/${id}/meta`);
  assert.strictEqual(meta.status, 404);

  const v3 = await req(port, 'POST', `/api/secrets/${id}/view`);
  assert.strictEqual(v3.status, 410);
});

test('server-side poison rejects without burning a view', async (t) => {
  const { server } = makeServer();
  const port = await listen(server);
  t.after(() => server.close());

  const created = await req(port, 'POST', '/api/secrets', {
    body: { ...sample, viewLimit: 3, ttlSeconds: 3600 },
  });
  const { id } = created.json;

  // View once and capture the poison token.
  const v1 = await req(port, 'POST', `/api/secrets/${id}/view`);
  const poison = v1.json.poison;
  assert.strictEqual(v1.json.remaining, 2);

  // Replaying the poison token is rejected (403) and does NOT consume a view.
  const replay = await req(port, 'POST', `/api/secrets/${id}/view`, {
    auth: poison,
  });
  assert.strictEqual(replay.status, 403);

  const meta = await req(port, 'GET', `/api/secrets/${id}/meta`);
  assert.strictEqual(meta.json.remaining, 2); // unchanged
});

test('validation rejects bad input', async (t) => {
  const { server } = makeServer();
  const port = await listen(server);
  t.after(() => server.close());

  const badLimit = await req(port, 'POST', '/api/secrets', {
    body: { ...sample, viewLimit: 0, ttlSeconds: 3600 },
  });
  assert.strictEqual(badLimit.status, 400);

  const badTtl = await req(port, 'POST', '/api/secrets', {
    body: { ...sample, viewLimit: 1, ttlSeconds: 5 },
  });
  assert.strictEqual(badTtl.status, 400);

  const badCipher = await req(port, 'POST', '/api/secrets', {
    body: { ciphertext: 'not base64!!', iv: sample.iv, viewLimit: 1, ttlSeconds: 3600 },
  });
  assert.strictEqual(badCipher.status, 400);
});
