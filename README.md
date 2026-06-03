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

For a standalone image build:

```bash
docker build -t zenmind-official-server .
docker run --env-file .env -p 8080:8080 zenmind-official-server
```
