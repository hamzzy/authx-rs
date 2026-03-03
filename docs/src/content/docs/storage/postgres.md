---
title: PostgreSQL
description: Production-ready PostgreSQL storage adapter via sqlx.
---

import { Aside } from '@astrojs/starlight/components';

`PostgresStore` wraps a `sqlx` connection pool and implements every repository trait. Enable it with the `sqlx-postgres` feature flag.

## Setup

```toml title="Cargo.toml"
authx-storage = { path = "crates/authx-storage", features = ["sqlx-postgres"] }
```

```rust
use authx_storage::sqlx::PostgresStore;

let store = PostgresStore::connect("postgres://user:pass@localhost/mydb").await?;

// Run bundled migrations (idempotent — safe to call on every startup)
PostgresStore::migrate(&store.pool).await?;
```

## Connection URL format

```
postgres://username:password@host:port/database?sslmode=require
```

| Component | Example | Notes |
|---|---|---|
| Username | `authx` | Needs CREATE / SELECT / INSERT / UPDATE / DELETE |
| Password | `secret` | URL-encode special chars |
| Host | `db.example.com` | |
| Port | `5432` | Default |
| Database | `myapp` | |
| SSL mode | `sslmode=require` | Required in production |

## Schema

Migrations run automatically from the embedded SQL files:

- `0001_initial_schema.sql` — users, sessions, credentials, orgs, roles, memberships, audit_logs
- `0002_.sql` — api_keys, oauth_accounts, invites, username column

All tables are prefixed with `authx_` to avoid conflicts with your own schema.

<Aside type="note">
`PostgresStore::migrate` uses `sqlx`'s built-in migration runner. It tracks applied migrations in a `_sqlx_migrations` table and only runs new ones.
</Aside>

## Using with the CLI

```bash
# Apply migrations without starting the server
authx migrate --database-url postgres://user:pass@host/db

# Start server with Postgres
DATABASE_URL=postgres://user:pass@host/db authx serve
```

## Connection pool

The default pool has `max_connections = 10`. Adjust by constructing the pool directly:

```rust
use sqlx::postgres::PgPoolOptions;

let pool = PgPoolOptions::new()
    .max_connections(25)
    .connect(&database_url)
    .await?;

let store = PostgresStore { pool };
```
