# Server Configs

This directory stores file-based runtime configuration for the server.

- `secrets/` is for local or deployment-provided key files such as JWT PEM files.
- Keep real private keys, tokens, certificates, and generated secrets out of Git.
- Keep environment variable values in the root `.env`; this directory is for files referenced by `.env`.
- Runtime data such as SQLite databases belongs in `../data/`, not in `configs/`.

The default container path for the Desktop SSO JWT private key is:

```dotenv
SSO_JWT_PRIVATE_KEY_FILE=/configs/secrets/zenmind-sso-jwt-private.pem
```
