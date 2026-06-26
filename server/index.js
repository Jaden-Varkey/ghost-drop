'use strict';

const path = require('path');
const express = require('express');
const config = require('./config');
const { createStore } = require('./store');
const { createSecretsRouter } = require('./routes/secrets');

async function main() {
  const app = express();

  if (config.trustProxy) app.set('trust proxy', 1);
  app.disable('x-powered-by');

  // Body parsing — ciphertext is small JSON; cap it generously above the
  // ciphertext limit to leave room for base64 + envelope overhead.
  app.use(express.json({ limit: Math.ceil(config.maxCiphertextBytes * 2) }));

  // Minimal security headers. The frontend is fully static and self-hosted,
  // so a tight CSP is easy here.
  app.use((req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'no-referrer');
    res.set(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'"
    );
    next();
  });

  const store = await createStore(console);

  app.get('/healthz', (req, res) => res.json({ ok: true }));
  app.use('/api/secrets', createSecretsRouter(store));

  // Static frontend.
  const publicDir = path.join(__dirname, '..', 'public');
  app.use(express.static(publicDir, { extensions: ['html'] }));

  // The view page is a single-page route: /view/:id is served by view.html,
  // which reads the id from the path and the key from the URL hash.
  app.get('/view/:id', (req, res) => {
    res.sendFile(path.join(publicDir, 'view.html'));
  });

  // JSON 404 for unmatched API routes; otherwise fall through to the SPA shell.
  app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
      return res.status(404).json({ error: 'not_found' });
    }
    res.status(404).sendFile(path.join(publicDir, 'index.html'));
  });

  // Centralized error handler — never leak internals or the ciphertext.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error('[error]', err);
    if (res.headersSent) return;
    res.status(500).json({ error: 'internal_error' });
  });

  const server = app.listen(config.port, config.host, () => {
    console.log(
      `GhostDrop listening on http://${config.host}:${config.port} ` +
        `(store: ${store.constructor.name})`
    );
  });

  // Graceful shutdown so Redis connections / timers are released.
  const shutdown = async (signal) => {
    console.log(`\n[shutdown] received ${signal}, closing...`);
    server.close(async () => {
      try {
        await store.close();
      } finally {
        process.exit(0);
      }
    });
    // Force-exit if something hangs.
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('[fatal] failed to start GhostDrop:', err);
  process.exit(1);
});
