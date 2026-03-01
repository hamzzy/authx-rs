---
title: Memory Store
description: In-memory storage adapter for development and testing.
---

`MemoryStore` is a fully-featured in-process storage adapter backed by `Arc<RwLock<Vec<T>>>` collections. It implements every repository trait authx-rs defines.

## Usage

```rust
use authx_storage::memory::MemoryStore;

let store = MemoryStore::new();

// Clone is cheap — all clones share the same in-memory data
let store2 = store.clone();
```

## When to use it

| Scenario | Suitable? |
|---|---|
| Unit and integration tests | ✅ — no DB setup, zero latency |
| Local development / prototyping | ✅ — start immediately |
| Production | ❌ — data is lost on restart |
| Multi-process deployments | ❌ — data is not shared across processes |

## In tests

```rust
#[tokio::test]
async fn sign_up_works() {
    let store  = MemoryStore::new();
    let events = EventBus::new();
    let svc    = EmailPasswordService::new(store, events, 3600);

    let user = svc.sign_up("alice@example.com", "password123").await.unwrap();
    assert_eq!(user.email, "alice@example.com");
}
```

## Thread safety

Every field is wrapped in `Arc<RwLock<_>>`. Reads acquire a shared lock; writes acquire an exclusive lock. Clones share all state — this is intentional so multiple service instances in the same process see the same data.
