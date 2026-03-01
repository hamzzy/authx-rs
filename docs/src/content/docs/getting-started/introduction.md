---
title: Introduction
description: What authx-rs is, why it exists, and how it compares to alternatives.
---

authx-rs is an **embedded authentication and authorization library** for Rust services. It ships as a set of composable crates you add to your own binary — not a standalone server you deploy separately.

## Philosophy

| Principle | What it means |
|---|---|
| Framework-agnostic core | `authx-core` has zero imports from Axum, Actix, or any HTTP library |
| Plugin-based | Every feature is opt-in. Unused plugins cost you nothing at compile time |
| Storage-agnostic | Repository traits define the contract; you supply the adapter |
| Async-first | Every I/O path is `async` — no blocking surprises |
| Security by default | Argon2id, EdDSA, AES-256-GCM, CSRF, and rate limiting are active unless you explicitly opt out |

## How it compares

| | authx-rs | Auth0 / Keycloak | Lucia | custom JWT middleware |
|---|---|---|---|---|
| Deployment | Embedded in your binary | Separate server | Embedded | Embedded |
| Full session management | ✅ | ✅ | ✅ | ❌ |
| Organizations / multi-tenancy | ✅ | ✅ | ❌ | ❌ |
| RBAC + ABAC | ✅ | ✅ | ❌ | ❌ |
| Audit logs | ✅ | ✅ | ❌ | ❌ |
| Brute-force lockout | ✅ | ✅ | ❌ | ❌ |
| Bring your own DB | ✅ | ❌ | ✅ | ✅ |
| No network call to auth | ✅ | ❌ | ✅ | ✅ |
| Rust type safety end-to-end | ✅ | ❌ | ❌ | ✅ |

## Workspace crates

```
authx-core       Zero-dep engine — models, crypto, events, RBAC/ABAC policy, identity
authx-storage    Repository traits + MemoryStore + PostgresStore + AuditLogger
authx-plugins    All auth plugins (email/password, TOTP, OAuth, API keys, …)
authx-axum       Tower middleware, route handlers, cookies, CSRF, rate limiting
authx-dashboard  Embedded HTMX admin dashboard
authx-cli        `authx` binary — serve, migrate, manage users
```
