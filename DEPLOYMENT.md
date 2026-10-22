# KeyCheck — Production Deployment Guide

Deploy KeyCheck to a Linux server running nginx. The app is served by uvicorn (via systemd) and nginx proxies requests to it. This runs **alongside** any existing sites on the same nginx — each app gets its own `server` block.

```
keycheck.example.com ──► nginx (server block for keycheck)
                             └── proxy_pass http://127.0.0.1:8000  (uvicorn via systemd)
```

## Prerequisites

- A server with nginx installed and running
- A domain/subdomain pointing at the server (A record: `keycheck` → server IP)
- Python 3.10+ on the server

## 1. Get the code on the server

```bash
# Option A: git clone
git clone <your-repo-url> /opt/keycheck

# Option B: rsync from your machine
rsync -av --exclude venv --exclude .env --exclude '*.db' ./ user@server:/opt/keycheck/
```

## 2. Set up the venv and environment

```bash
cd /opt/keycheck
python3 -m venv venv
venv/bin/pip install pip-tools
venv/bin/pip-compile requirements.in --strip-extras && venv/bin/pip-sync
```

Create `/opt/keycheck/.env` with real secrets (copy from `.env.example` and change every value):

```bash
cp .env.example .env
nano .env
```

> The app **fails to start** if `KEYCHECK_ADMIN_TOKEN`, `KEYCHECK_ADMIN_USER`,
> `KEYCHECK_ADMIN_PASSWORD`, or `KEYCHECK_JWT_SECRET` are missing — so a blank
> `.env` is caught immediately, not in production.

### 2a. The signing seed (for signed product keys)

If this service will issue `CLN1-` product keys for the Clinic Manager app, it
also needs the Ed25519 **signing seed**:

```bash
KEYCHECK_LICENSE_SEED=<64 hex characters>
```

This is the same seed as `%LOCALAPPDATA%\ClinicManager-keys\vendor.key` on the
vendor machine. Get it with:

```powershell
# on the vendor machine
type $env:LOCALAPPDATA\ClinicManager-keys\vendor.key
```

> **Treat this like a password, not a config value.**
>
> * **Lose it** and no further keys can be issued for the current app build —
>   every customer would need a rebuilt app with a new public key.
> * **Leak it** and anyone can mint keys the app will happily accept.
>
> It lives in `.env`, which is gitignored. Do not put it in the repo, in
> `DEPLOYMENT.md`, in a shell history you paste around, or in a chat message.
> `KEYCHECK_LICENSE_PUBLIC_KEY` is the safe companion value to set too: it
> pins the key the app was built with, so a seed that disagrees is caught at
> issue time instead of on a customer's machine.

The seed is optional. Without it, `/api/keys/sign` returns `503` and
`/api/keys/verify` returns `503`, but key checking, listing and revoking all
work exactly as before.

## 2b. Database schema

There is no migration tool. On startup the service:

1. creates any missing table (`Base.metadata.create_all`), then
2. adds any missing column to `license_keys` (`app/migrations.py`).

Step 2 exists because `create_all` will *not* add a column to a table that
already exists. On a server that predates the signed-key columns, the columns
(`kind`, `clinic`, `serial`, `machine_code`, `activated_at`) are added
automatically and existing rows are marked `kind = 'random'`. The operation is
idempotent and safe to run on every start.

Check it took effect:

```bash
curl http://127.0.0.1:8000/health
# {"status":"ok","problems":[]}
```

`status: "degraded"` means the schema is not current — check the service logs.

## 3. systemd unit

Create `/etc/systemd/system/keycheck.service`:

```ini
[Unit]
Description=KeyCheck API
After=network.target

[Service]
WorkingDirectory=/opt/keycheck
EnvironmentFile=/opt/keycheck/.env
ExecStart=/opt/keycheck/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now keycheck
```

Useful commands:

```bash
sudo systemctl status keycheck     # check status
sudo journalctl -u keycheck -f     # follow logs
sudo systemctl restart keycheck    # restart after updates
```

## 4. nginx server block

Create `/etc/nginx/sites-available/keycheck`:

```nginx
server {
    listen 80;
    server_name keycheck.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable it (this does not touch your existing site's config):

```bash
sudo ln -s /etc/nginx/sites-available/keycheck /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

> Each app gets its own file in `sites-available/` plus a symlink in
> `sites-enabled/`. Make sure `server_name` differs from your other sites.

## 5. HTTPS (optional but recommended)

Once DNS propagates:

```bash
sudo certbot --nginx -d keycheck.example.com
```

Certbot rewrites the server block with TLS automatically and sets up renewal.

## 6. Verify

```bash
# from the server
curl http://127.0.0.1:8000/          # uvicorn is up → JSON message
curl http://127.0.0.1:8000/health     # service up and schema current
curl http://127.0.0.1:8000/login     # page loads

# from a browser
https://keycheck.example.com/login   # sign in (user/pass from .env)
https://keycheck.example.com/dashboard
```

## 7. Issuing a signed product key

There are two ways: the **web page** at `https://keycheck.example.com/signed-keys`
(reachable from the *Clinic Manager keys* link in the dashboard header), or the
API with `curl`.

The page is the simpler route: enter the clinic name, a serial, and the machine
code from the customer's activation screen, then press **Issue key**. It shows
the key with a copy button and lists previously issued keys. Leaving the machine
code blank produces a site-wide key. The page only ever shows signed keys — the
legacy random keys stay on the dashboard page.

The key list is durable: every row keeps its full key text, so **Show key** or
**Copy** retrieves it at any time, even after a reload. Revoking a row is a
bookkeeping flag only (see the note at the end of this section) and can be
undone with **Un-revoke**.

The customer's app shows a **machine code** on its activation screen. That code
is what the key is bound to, so ask the customer for it and include it in the
request:

```bash
curl -X POST https://keycheck.example.com/api/keys/sign \
  -H "Authorization: Bearer $KEYCHECK_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"clinic": "John'"'"'s Eye Clinic", "serial": "0007", "machine_code": "3ARN-47PE-L5RN-WPVU"}'
```

```json
{
  "key": "CLN1-PMRGG3DJNZUWGIR...WYTALJSGIRCYITNMFRWQ2LOMURDUISLG5DDEOKRLBGTGQSSIQRCYITTMVZ",
  "clinic": "John's Eye Clinic",
  "serial": "0007",
  "machine_code": "3ARN-47PE-L5RN-WPVU",
  "machine_bound": true,
  "issued": "2026-10-22"
}
```

Send the `key` to the customer. Their app verifies it **offline** — it never
contacts this server.

Notes:

* **Omit `machine_code` for a site-wide key** that activates any machine. That
  is a break-glass option, not the normal case.
* A malformed machine code is rejected with `422` and an explanation, rather
  than silently producing a key that can never activate.
* The same request on the **same day** produces the **same key** (Ed25519 is
  deterministic and `issued` is a date). On a later day it produces a different
  but equally valid key for the same machine. To re-send a lost key, prefer
  **Copy** on the stored row — that returns the exact key the customer already
  has. Re-issuing never invalidates anything.
* Verifying a key (`/api/keys/verify`) is pure cryptography and never consumes
  a use, so it is safe to call repeatedly.

To check a key without activating anything:

```bash
curl -X POST https://keycheck.example.com/api/keys/verify \
  -H "Content-Type: application/json" \
  -d '{"key": "CLN1-...", "machine_code": "3ARN-47PE-L5RN-WPVU"}'
```

> **Do not send a signed key to `/api/keys/check`.** That endpoint consumes a
> use from its counter, and `max_uses` defaults to 1 — one activation *ever* —
> so a reinstall would burn the key. The endpoint refuses signed keys with a
> pointer to `/verify`; the dashboard routes them automatically.

## Updating the app

```bash
cd /opt/keycheck
git pull                                  # or rsync new files
venv/bin/pip-sync                         # if dependencies changed
sudo systemctl restart keycheck
```

The schema is brought up to date automatically on restart (see §2b). Confirm
afterwards:

```bash
curl http://127.0.0.1:8000/health
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Missing required env var: ...` in logs | `.env` missing or incomplete | Fill in `/opt/keycheck/.env` |
| `502 Bad Gateway` | uvicorn not running or on wrong port | `systemctl status keycheck`; check `--port 8000` matches `proxy_pass` |
| Wrong site served | `server_name` conflict | Ensure `server_name keycheck.example.com` is unique |
| Permissions errors on DB/static | `www-data` can't write | `sudo chown -R www-data:www-data /opt/keycheck` |
| `/api/keys/sign` returns `503` | `KEYCHECK_LICENSE_SEED` unset or malformed | The message says which. The seed must be 64 hex characters |
| `/api/keys/verify` returns `503` | No seed and no `KEYCHECK_LICENSE_PUBLIC_KEY` | Set one of them |
| App rejects a key the server says is valid | The app's public key and the server's seed disagree | Check `KEYCHECK_LICENSE_PUBLIC_KEY` against the app's `LICENSE_PUBLIC_KEY`. They are different values: the seed signs, the public key verifies |
| `/health` says `degraded` | Schema not migrated | Check the service logs; the migration runs automatically at startup |
| A customer's key stopped working | The seed was regenerated | The seed is the only thing that can sign; a changed seed means every previously issued key is invalid |
