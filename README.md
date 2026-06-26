# GhostDrop 👻

[![CI](https://github.com/Jaden-Varkey/ghost-drop/actions/workflows/ci.yml/badge.svg)](https://github.com/Jaden-Varkey/ghost-drop/actions/workflows/ci.yml)
[![Docker](https://github.com/Jaden-Varkey/ghost-drop/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Jaden-Varkey/ghost-drop/actions/workflows/docker-publish.yml)

Frictionless, **zero-knowledge** multi-view secret sharing.

**[Live demo]([https://ghostdrop-demo.onrender.com](https://ghost-drop-kj83.onrender.com))** · hosted on Render free tier 
(may spin down after inactivity; first load can take ~30s). Uses an in-memory store,
so secrets do not persist across restarts.

Share a password or API key with a small group using a single link. The secret
is encrypted **in the browser** (the server only ever sees ciphertext), can be
opened a predefined number of times, and is **permanently destroyed** the moment
the last view is consumed or the expiry is reached. A per-device "poison" marker
stops one recipient from burning every view by accidentally refreshing.

## Stack

- **Backend:** Rust ([axum](https://github.com/tokio-rs/axum) + Tokio), Redis
  for the token list + TTL, HMAC-SHA256 for poison tokens.
- **Frontend:** static HTML/CSS/JS with the WebCrypto API — no build step.

## Quick start

```bash
# Run it. With no Redis running, GhostDrop falls back to an in-memory store
# automatically — great for trying it out. Add --release for an optimized build.
cargo run
# open http://localhost:3000

# For persistence / multiple instances, start a Redis and point GhostDrop at it:
docker run -p 6379:6379 redis:7-alpine
STORE_DRIVER=redis REDIS_URL=redis://127.0.0.1:6379 cargo run --release
```

Or run everything (app + Redis) with Docker Compose:

```bash
JWT_SECRET=$(openssl rand -hex 32) docker compose up --build   # bash
```

```powershell
$env:JWT_SECRET = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }); docker compose up --build   # PowerShell
```

Or run the prebuilt image — no toolchain, no build:

```bash
docker run -p 3000:3000 ghcr.io/jaden-varkey/ghost-drop:latest
# open http://localhost:3000
```

## Deploy

One click, free tier, no database required (uses the in-memory store):

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Jaden-Varkey/ghost-drop)

## How it works

1. **Zero-knowledge setup** — the sender's browser encrypts the secret with
   AES-256-GCM (WebCrypto). The raw key is placed in the URL **hash** and never
   sent to the server.
2. **Ticket dispensing** — the backend stores the ciphertext and a list of N
   single-use tokens, both with a TTL guaranteeing deletion at the chosen
   expiry.
3. **Link** — `https://host/view/<id>#<key>`.
4. **Poison check** — before any network call, the viewer's browser checks
   LocalStorage **and** IndexedDB for a poison token tied to that secret id. If
   found, the API call never fires.
5. **Decryption & poisoning** — on a clean device the server pops one token
   (atomically), returns the ciphertext plus a signed poison token; the browser
   persists the poison in both stores, then decrypts locally with the hash key.
   The server also rejects any request that replays a valid poison token, so the
   authority is server-side, not just client friction.
6. **Final destruction** — when the token list hits 0, the ciphertext is wiped.

## Configuration

Copy `.env.example` to `.env`. Key settings:

| Variable               | Default                    | Purpose                                            |
| ---------------------- | -------------------------- | -------------------------------------------------- |
| `PORT`                 | `3000`                     | HTTP port                                          |
| `STORE_DRIVER`         | `auto`                     | `auto` \| `redis` \| `memory`                      |
| `REDIS_URL`            | `redis://127.0.0.1:6379`   | Redis connection string                            |
| `JWT_SECRET`           | _(ephemeral)_              | Signs poison tokens — **set this in production**   |
| `MAX_VIEW_LIMIT`       | `100`                      | Max views a sender may request                     |
| `MIN/MAX_TTL_SECONDS`  | `60` / `2592000`           | Allowed expiry range                               |
| `MAX_CIPHERTEXT_BYTES` | `65536`                    | Max ciphertext size                                |

> **Note:** with the in-memory store, an ephemeral `JWT_SECRET`, or a Redis
> restart, existing poison tokens / secrets are lost. Set `JWT_SECRET` and use
> Redis for any real deployment.

## API

| Method & path                | Body / auth                                   | Result                                                  |
| ---------------------------- | --------------------------------------------- | ------------------------------------------------------- |
| `POST /api/secrets`          | `{ ciphertext, iv, viewLimit, ttlSeconds }`   | `201 { id }` — ciphertext only, no key                  |
| `GET /api/secrets/:id/meta`  | —                                             | `{ remaining, expiresAt }` or `404` (non-destructive)   |
| `POST /api/secrets/:id/view` | optional `Authorization: Bearer <poison>`     | `{ ciphertext, iv, remaining, poison }`, `403`, or `410`|

## Testing

```bash
cargo test
```

Covers the create → multi-view → destruction lifecycle and poison
sign/verify (including expiry rejection).

## Security model & limitations

- **The link is the secret.** Anyone with the full URL (including the `#key`)
  can view it, up to the view limit. Share it over a trusted channel.
- **Zero-knowledge** is real for the server, but the key passes through whatever
  renders the link (chat app, email). The server never logs the hash.
- **Poison is per-device, best-effort on the client** (LocalStorage +
  IndexedDB) and **enforced on the server** via signed tokens. A determined user
  with a fresh browser profile / incognito counts as a new device — that is by
  design (one view *per device*), bounded by the hard server-side view limit.
- Not included (add for production): rate limiting / abuse protection,
  persistent audit logging, and HTTPS termination (run behind a TLS proxy).
