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
curl http://127.0.0.1:8000/login     # page loads

# from a browser
https://keycheck.example.com/login   # sign in (user/pass from .env)
https://keycheck.example.com/dashboard
```

## Updating the app

```bash
cd /opt/keycheck
git pull                                  # or rsync new files
venv/bin/pip-sync                         # if dependencies changed
sudo systemctl restart keycheck
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Missing required env var: ...` in logs | `.env` missing or incomplete | Fill in `/opt/keycheck/.env` |
| `502 Bad Gateway` | uvicorn not running or on wrong port | `systemctl status keycheck`; check `--port 8000` matches `proxy_pass` |
| Wrong site served | `server_name` conflict | Ensure `server_name keycheck.example.com` is unique |
| Permissions errors on DB/static | `www-data` can't write | `sudo chown -R www-data:www-data /opt/keycheck` |
