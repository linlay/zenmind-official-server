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
- `GET /api/auth/google/start`
- `GET /api/auth/google/callback`
- `GET /api/auth/me`
- `POST /api/auth/logout`

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

Create a MySQL user with a strong password, then set the same value in `MYSQL_PASSWORD`:

```sql
CREATE USER 'zenmind'@'%' IDENTIFIED BY '<set-a-strong-password>';
GRANT ALL PRIVILEGES ON zenmind_website.* TO 'zenmind'@'%';
```

The matching initialization script lives in `deploy/mysql/init/01-auth.sql`; replace its password placeholder before using it outside local development.

## Development

```bash
go test ./...
go run ./cmd/server
```

## Container

```bash
docker build -t zenmind-official-server .
docker run --env-file .env -p 8080:8080 zenmind-official-server
```

This project does not include a cross-project Compose file. Run MySQL separately or provide it through your deployment platform.
