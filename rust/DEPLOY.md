# Deploying on a Docker host (e.g. the NAS)

Sign in to Google once, on the host. Every machine on your tailnet then uses
`https://gmail.<tailnet>.ts.net/mcp` with no login.

## One-time setup

```bash
git clone https://github.com/natesena/Gmail-MCP-Server && cd Gmail-MCP-Server/rust
cp .env.example .env                 # set GMAIL_MCP_ALLOWED_LOGINS to your Tailscale login
docker compose build gmail
mkdir -p secrets && chmod 700 secrets
docker run --rm gmail-mcp:local gmail-mcp store keygen > secrets/gmail_store_key
chmod 600 secrets/gmail_store_key    # back this key up somewhere safe: without it the store is unreadable
docker compose up -d
```

Joining the tailnet: either set `TS_AUTHKEY` in `.env`, or log in once with a
link. Don't use the link printed by `docker compose logs tailscale`: the
container's startup script gives up after about a minute and throws that link
away. Instead:

```bash
docker run -d --name ts-login -v gmail-mcp_tailscale-state:/var/lib/tailscale tailscale/tailscale:v1.90.6 \
  tailscaled --tun=userspace-networking --statedir=/var/lib/tailscale --socket=/tmp/ts.sock
docker exec ts-login tailscale --socket=/tmp/ts.sock up --hostname=gmail --timeout=0   # open the link, approve
docker rm -f ts-login && docker compose up -d
```

Then disable key expiry for the `gmail` machine in the Tailscale admin console.

## Accounts (run on the host)

```bash
# Reuse an existing credentials dir (gcp-oauth.keys.json + credentials.json); no Google login:
docker compose run --rm -v ~/.gmail-work:/import:ro gmail gmail-mcp accounts import work /import

# Sign in to a new account: open the printed link in any browser, approve,
# then paste back the address of the page it lands on:
docker compose exec -it gmail gmail-mcp accounts add personal

docker compose exec gmail gmail-mcp accounts list
docker compose exec gmail gmail-mcp accounts default personal
docker compose exec gmail gmail-mcp accounts remove old
```

The running server picks up account changes immediately; no restart needed.

## Each client machine (no login)

```bash
claude mcp add --transport http -s user gmail https://gmail.<tailnet>.ts.net/mcp
```

Other harnesses: add the same URL as a Streamable HTTP MCP server.

## Updating

```bash
git pull && docker compose up -d --build
```

## What lives where

| Thing | Where |
|---|---|
| Google tokens + OAuth client | `gmail-data` volume, AES-256-GCM encrypted (`/data/store.json`) |
| Store key | `secrets/gmail_store_key` on the host (git-ignored) |
| Tailscale node state | `tailscale-state` volume |
| Who may call | `GMAIL_MCP_ALLOWED_LOGINS` in `.env` |
