# ZenMind Official Server

Go 1.26 backend for the ZenMind official site login flow.

## Features

- MySQL-backed users and sessions
- Google OIDC with server-side State, Nonce, and PKCE verification
- Email verification-code login and verified-email identity linking
- Initial administrator bootstrap from environment variables
- bcrypt password verification
- 24-hour Secure, HttpOnly, SameSite=Lax, host-only cookie sessions
- One-time Desktop tickets and 12-hour multi-service JWTs
- Same-origin Market gateway with 90-second Market-only JWTs
- Temporary Authentik forward-auth bridge for rollback only

## API

- `GET /api/health`
- `GET /api/updates/desktop-latest.json`
- `POST /api/auth/login`
- `POST /api/auth/email-code/start`
- `POST /api/auth/email-code/verify`
- `GET /api/auth/google/start`
- `GET /api/auth/google/callback`
- `GET /api/auth/google/desktop/start`
- `GET /api/auth/desktop-sso/start`
- `GET /api/auth/desktop-sso/continue`
- `POST /api/auth/desktop-sso/session`
- `POST /api/auth/desktop-sso/token`
- `GET /api/auth/sso/session`
- `GET /api/auth/csrf`
- `GET /api/auth/me`
- `GET /api/auth/avatar/{version}`
- `POST /api/auth/logout`
- `/api/market/*`
- `GET /api/downloads/stats`
- `POST /api/downloads/events`

## Environment

Copy `.env.example` and provide production values before deployment.

```bash
cp .env.example .env
```

Configuration and runtime files are split by responsibility:

- `.env` is the main local and deployment configuration entrypoint; it is not committed.
- `configs/` stores file-based configuration referenced by `.env`, such as PEM files.
- `data/` stores runtime data only, such as the SQLite site data store and WAL files.

Required values:

- `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`
- `INIT_ADMIN_EMAIL`, `INIT_ADMIN_PASSWORD`
- `COOKIE_NAME`, `COOKIE_SECURE`, `SESSION_TTL`
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URL`
- `SSO_BRIDGE_TOKEN` matching the website nginx bridge token only while the Authentik rollback bridge remains enabled
- `DESKTOP_SSO_PROVIDER`, defaulting to `first_party`
- `DESKTOP_SSO_TICKET_TTL`, defaulting to `2m`
- `SSO_JWT_PRIVATE_KEY_FILE` or `SSO_JWT_PRIVATE_KEY_PEM`, plus explicit `SSO_JWT_ISSUER`, for Desktop and Market gateway JWT signing. The default file path is `/configs/secrets/zenmind-sso-jwt-private.pem` in the container.
- `SSO_JWT_AUDIENCES`, defaulting to `market,tunnel,kanban,zenmind-im-server`; `SSO_JWT_TTL`, defaulting to `12h`; `SSO_JWT_KEY_ID`, defaulting to `default`
- `MARKET_SERVER_URL`, `MARKET_JWT_AUDIENCE=market`, and `MARKET_JWT_TTL=90s`
- `TRUSTED_PROXY_CIDRS`, restricted to the deployment Docker network such as `172.20.0.0/16`
- `AUTH_SUCCESS_URL`, `AUTH_FAILURE_URL`
- `AUTH_PUBLIC_ORIGIN` for absolute public API URLs such as the authenticated avatar endpoint
- `AVATAR_PROXY_ENABLED`, `AVATAR_UPSTREAM_ORIGINS`, and `AVATAR_CACHE_DIR`; production
  serves provider avatars through the authenticated `/api/auth/avatar/{version}` route
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`
- `SQLITE_DB_PATH` for the local SQLite site data store, defaulting to `/data/data.sqlite` in the container

Optional values:

- `GOOGLE_DESKTOP_CLIENT_ID` when the desktop app uses a separate Google OAuth client id

Avatar proxy downloads are restricted to the exact HTTPS origins in
`AVATAR_UPSTREAM_ORIGINS`. Cached files are stored under `AVATAR_CACHE_DIR`
(`/data/avatars` by default); the raw provider URL remains server-side and
authenticated user responses expose only the `AUTH_PUBLIC_ORIGIN` avatar URL.
`GET /api/auth/avatar/{version}` requires the current website session Cookie;
accounts without an avatar URL continue to receive an empty `avatarUrl`.

The Google web client must register the exact callback configured by
`GOOGLE_REDIRECT_URL`; production uses
`https://www.zenmind.cc/api/auth/google/callback`.

For Gmail delivery, set `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_USERNAME=linlay.zenmind@gmail.com`, `SMTP_FROM=linlay.zenmind@gmail.com`, and use a Google App Password as `SMTP_PASSWORD`. Do not use the normal Google account password.

Compose only deploys the Go server. MySQL is expected to be provided separately; set `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, and `MYSQL_PASSWORD` to the provided database server. The schema initialization script lives in `deploy/mysql/init/01-auth.sql`.

## Development

```bash
go test ./...
go run ./cmd/server
```

## Container

Create the shared deployment network once:

```bash
docker network create zenmind-official-net
```

Run the server container:

```bash
docker compose up --build
```

The `server` service joins `zenmind-official-net` as `zenmind-official-server`. The host port defaults to `8080` and can be overridden with `SERVER_PORT`.
The SQLite site data store is persisted through `./data:/data`, and file-based configuration is mounted read-only through `./configs:/configs:ro`; override the container user with `SERVER_USER` if the host deployment user is not `1000:1000`.

## Installer releases

The public installer catalog is served from `GET /api/installers`. Installer records live in the `installer` table inside the site SQLite database, while download event details and aggregate counts live in `download` and `download_stat`. Release files should live under `/docker/zenmind-releases/desktop/{version}/{fileName}` on the host, which maps to `/install/releases/desktop/{version}/{fileName}` publicly.

Initialize or repair the current macOS record:

```bash
go run ./cmd/releasectl upsert \
  --key mac \
  --version 0.2.4 \
  --source /docker/zenmind-releases/v0.2/ZenMind-0.2.4-arm64.dmg \
  --filename ZenMind-macOS-arm64.dmg
```

Upload and publish a Windows installer:

```bash
scp -p ./ZenMind-0.2.4-x64.exe singapore02:/tmp/ZenMind-0.2.4-x64.exe
ssh singapore02 'cd /docker/zenmind-official-server && go run ./cmd/releasectl upsert --key windows --version 0.2.4 --source /tmp/ZenMind-0.2.4-x64.exe --filename ZenMind-0.2.4-x64.exe'
```

For a standalone image build:

```bash
docker build -t zenmind-official-server .
docker run --env-file .env -p 8080:8080 zenmind-official-server
```

## Named update feeds and Admin

`GET /api/updates/{name}` publicly serves one named Desktop v1 manifest directly,
without a `data` wrapper. Names are unique lowercase letters/numbers/hyphens ending
in `.json`, for example `desktop-latest.json` and `desktop-beta.json`. Names are
stable identifiers, never filesystem paths. An absent/disabled feed returns 404;
invalid storage returns 503. All public and Admin responses use `Cache-Control:
no-store` so enable/disable takes effect without stale cached metadata.

Admin APIs (valid enabled administrator Cookie session required on every request):

- `GET /api/admin/updates`: list feed metadata.
- `GET /api/admin/updates/{name}`: current metadata and manifest.
- `GET /api/admin/updates/{name}/history`: last 20 immutable revisions.
- `PUT /api/admin/updates/{name}`: create/update with `{description, enabled,
  revision, manifest}`. Also requires session `X-CSRF-Token` and valid Origin.

Use `revision: 0` to create; updates must submit the current revision. Stale saves
return 409 without changing anything. Name cannot be renamed; create a different
name if a new public URL is needed. A save to an enabled feed immediately changes
its public response. Disabling is an audited revision too. Restoring historical
content means saving it as a new revision against the current revision number.

`update_feed` owns each current pointer; `update_feed_revision` stores complete
immutable snapshots, description, enabled state, timestamp and administrator user
ID. Both writes share one transaction. Startup migrates the previous singleton
once to `desktop-latest.json`, preserving its current pointer and all legacy
history, and retains legacy tables as migration evidence. Empty stores stay empty.

The manifest uses `schemaVersion: 1`, `productId`, `channel`, semantic `version`,
`publishedAt`, localized `releaseNotes`, and platform/architecture `artifacts`
with absolute HTTPS `url`, byte `size`, and `sha256`. Stable rejects prereleases;
beta and other explicitly named channels allow valid prerelease SemVer. Clients
must configure a matching channel; filenames do not implicitly select channels.
macOS uses ZIP, Windows EXE. The existing `/api/installers` DMG catalog is separate.

Admin edits only metadata: upload and verify actual signed artifacts before
saving an enabled feed. This API never fetches arbitrary URLs or uploads binaries,
and does not claim to verify remote artifact bytes. Desktop verifies downloaded
bytes and platform signatures. No releasectl command was added. The frontend
management UI is in the sibling `zenmind-official-website` Admin page.
