---
title: authx CLI
description: Command-line tool for serving, migrating, and managing an authx-rs instance.
---

The `authx` binary (`authx-cli` crate) provides a full CLI for running and managing an authx-rs server.

## Installation

```bash
cargo install --path crates/authx-cli
# or, once published:
cargo install authx-cli
```

## Commands

### `authx serve`

Start the HTTP server.

```bash
authx serve [OPTIONS]

Options:
  --bind <BIND>                   Bind address [env: AUTHX_BIND] [default: 0.0.0.0:3000]
  --database-url <DATABASE_URL>   Postgres URL [env: DATABASE_URL]
  --trusted-origins <ORIGINS>     Comma-separated CSRF origins [env: AUTHX_TRUSTED_ORIGINS]
  --session-ttl <SECS>            Session TTL seconds [default: 2592000]
  --remember-me-ttl <SECS>        Remember-me TTL seconds [default: 7776000]
  --secure-cookies                Enable Secure cookie flag
  --rate-limit <N>                Requests/IP/minute [default: 30]
  --lockout-failures <N>          Failures before lockout [default: 5]
  --lockout-minutes <N>           Lockout window minutes [default: 15]
```

**Example:**

```bash
DATABASE_URL=postgres://user:pass@db/authx \
AUTHX_TRUSTED_ORIGINS=https://app.example.com \
authx serve --bind 0.0.0.0:8080 --secure-cookies
```

Without `DATABASE_URL`, the server uses an in-memory store (useful for development).

---

### `authx migrate`

Apply pending database migrations.

```bash
authx migrate --database-url postgres://user:pass@host/db
# or via env:
DATABASE_URL=postgres://… authx migrate
```

Run this before starting the server for the first time, and after every upgrade.

---

### `authx user list`

```bash
authx user list [--offset N] [--limit N]
```

---

### `authx user create`

```bash
authx user create <email> [--username <username>]
```

---

### `authx key generate`

Generate a new API key for a user. The raw key is printed once.

```bash
authx key generate <user-uuid> [--name "CI pipeline"] [--scopes "read,write"]
```

---

### `authx key list`

```bash
authx key list <user-uuid>
```

---

### `authx key revoke`

```bash
authx key revoke <user-uuid> <key-uuid>
```

## Environment variables

All `--flag` options have `env:` equivalents — see `authx serve --help` for the full list. A `.env` file is supported if you load it before invoking the binary (e.g. via `dotenv`).

For OIDC federation provider creation/encryption flows, set:

```bash
export AUTHX_ENCRYPTION_KEY="$(openssl rand -hex 32)"
```
