# GhostDrop 👻

Frictionless, **zero-knowledge** multi-view secret sharing.

Share a password or API key with a small group using a single link. The secret
is encrypted **in the browser** (the server only ever sees ciphertext), can be
opened a predefined number of times, and is **permanently destroyed** the moment
the last view is consumed or the expiry is reached. A per-device "poison" marker
stops one recipient from burning every view by refreshing.

## How it works

1. **Zero-knowledge setup** — the sender's browser encrypts the secret with
   AES-GCM (WebCrypto). The raw key is placed in the URL **hash** and never sent
   to the server.
2. **Ticket dispensing** — the backend stores the ciphertext and a list of N
   single-use tokens, both with a TTL guaranteeing deletion at the chosen
   expiry.
3. **Link** — `https://host/view/<id>#<key>`.
4. **Poison check** — before any network call, the viewer's browser checks
   LocalStorage **and** IndexedDB for a poison token tied to that secret id. If
   found, the API call never fires.
5. **Decryption & poisoning** — on a clean device the server pops one token
   (atomically), returns the ciphertext plus a signed poison JWT; the browser
   persists the poison in both stores, then decrypts locally with the hash key.
   The server also rejects any request that replays a valid poison token, so the
   authority is server-side, not just client friction.
6. **Final destruction** — when the token list hits 0, the ciphertext is wiped.

## Quick start

```bash
npm install
npm start
# open http://localhost:3000
```

With **no Redis running**, the default `STORE_DRIVER=auto` transparently falls
back to an in-memory store — great for trying it out. For production or
multi-instance deployments, use Redis (see below).

### With Redis

```bash
# start a local Redis (Docker)
docker run -p 6379:6379 redis:7-alpine

# point GhostDrop at it and require it
STORE_DRIVER=redis REDIS_URL=redis://127.0.0.1:6379 npm start
```

### Docker Compose (app + Redis)

```bash
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))") \
  docker compose up --build
```

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

| Method & path                | Body / auth                                   | Result                                              |
| ---------------------------- | --------------------------------------------- | --------------------------------------------------- |
| `POST /api/secrets`          | `{ ciphertext, iv, viewLimit, ttlSeconds }`   | `201 { id }` — ciphertext only, no key              |
| `GET /api/secrets/:id/meta`  | —                                             | `{ remaining, expiresAt }` or `404` (non-destructive) |
| `POST /api/secrets/:id/view` | optional `Authorization: Bearer <poison>`     | `{ ciphertext, iv, remaining, poison }`, `403`, or `410` |

## Testing

```bash
npm test
```

Covers the create → multi-view → destruction lifecycle, server-side poison
rejection, and input validation.

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
  persistent audit logging, and HTTPS termination (run behind a TLS proxy and
  set `TRUST_PROXY=true`).
```
