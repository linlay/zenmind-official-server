# ZenMind Official Server

Go 1.26 backend for the ZenMind official site login flow.

## Features

- MySQL-backed users and sessions
- Initial administrator bootstrap from environment variables
- bcrypt password verification
- HttpOnly SameSite=Lax cookie sessions

## API

- `GET /api/health`
- `POST /api/auth/login`
- `POST /api/auth/email-code/start`
- `POST /api/auth/email-code/verify`
- `GET /api/auth/google/start`
- `GET /api/auth/google/callback`
- `GET /api/auth/google/desktop/start`
- `POST /api/auth/desktop-sso/session`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `GET /api/downloads/stats`
- `POST /api/downloads/events`

## Environment

Copy `.env.example` and provide production values before deployment.

```bash
cp .env.example .env
```

Required values:

- `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`
- `INIT_ADMIN_EMAIL`, `INIT_ADMIN_PASSWORD`
- `COOKIE_NAME`, `COOKIE_SECURE`, `SESSION_TTL`
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URL`
- `AUTH_SUCCESS_URL`, `AUTH_FAILURE_URL`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`
- `SQLITE_DB_PATH` for the local SQLite site data store, defaulting to `/data/data.sqlite` in the container

Optional values:

- `GOOGLE_DESKTOP_CLIENT_ID` when the desktop app uses a separate Google OAuth client id
- `INSTALLER_DB_PATH` as a legacy fallback for existing deployments that still point to `/data/installers.sqlite`

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
The SQLite site data store is persisted through `./data:/data`; override the container user with `SERVER_USER` if the host deployment user is not `1000:1000`.

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
