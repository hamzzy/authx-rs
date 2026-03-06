---
title: "@authx-rs/sdk-web"
description: "Generated API reference for @authx-rs/sdk-web."
---

Generated from `packages/authx-sdk-web/dist/types`.

Browser token storage, authenticated fetch, and refresh orchestration.

## Modules

- [`errors`](#errors)
- [`oidc`](#oidc)
- [`storage`](#storage)
- [`token-manager`](#token-manager)

### errors

#### `AuthxTokenManagerError`

```ts
export declare class AuthxTokenManagerError extends Error {
    readonly cause?: unknown;
    constructor(message: string, options?: {
        cause?: unknown;
    });
}
```

### oidc

#### `OidcTokenRefresherOptions`

```ts
export interface OidcTokenRefresherOptions {
    tokenEndpoint: string;
    clientId: string;
    clientSecret?: string;
    scope?: string;
    headers?: HeadersInit;
    fetch?: typeof globalThis.fetch;
}
```

#### `createOidcTokenRefresher`

```ts
export declare function createOidcTokenRefresher(options: OidcTokenRefresherOptions): TokenRefreshHandler;
```

### storage

#### `TokenStore`

```ts
export interface TokenStore {
    load(): StoredTokenState | null | Promise<StoredTokenState | null>;
    save(tokens: StoredTokenState | null): void | Promise<void>;
}
```

#### `StorageLike`

```ts
export interface StorageLike {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
}
```

#### `BrowserStorageTokenStoreOptions`

```ts
export interface BrowserStorageTokenStoreOptions {
    key?: string;
    storage?: StorageLike;
}
```

#### `MemoryTokenStore`

```ts
export declare class MemoryTokenStore implements TokenStore {
    constructor(initialValue?: StoredTokenState | null);
    load(): StoredTokenState | null;
    save(tokens: StoredTokenState | null): void;
}
```

#### `BrowserStorageTokenStore`

```ts
export declare class BrowserStorageTokenStore implements TokenStore {
    constructor(options?: BrowserStorageTokenStoreOptions);
    load(): StoredTokenState | null;
    save(tokens: StoredTokenState | null): void;
}
```

### token-manager

#### `OidcTokenResponse`

```ts
export interface OidcTokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
    [key: string]: unknown;
}
```

#### `StoredTokenState`

```ts
export interface StoredTokenState {
    accessToken: string;
    tokenType: string;
    expiresAt: number;
    refreshToken?: string;
    scope?: string;
    idToken?: string;
    [key: string]: unknown;
}
```

#### `AuthxTokenSnapshot`

```ts
export interface AuthxTokenSnapshot {
    tokens: StoredTokenState | null;
    isAuthenticated: boolean;
    isRefreshing: boolean;
    error?: unknown;
}
```

#### `AuthxFetchOptions`

```ts
export interface AuthxFetchOptions {
    minValidityMs?: number;
    retryOnUnauthorized?: boolean;
}
```

#### `SetTokenResponseOptions`

```ts
export interface SetTokenResponseOptions {
    now?: number;
    preserveRefreshToken?: boolean;
}
```

#### `TokenRefreshHandler`

```ts
export type TokenRefreshHandler = (tokens: StoredTokenState) => Promise<OidcTokenResponse> | OidcTokenResponse;
```

#### `AuthxTokenManagerOptions`

```ts
export interface AuthxTokenManagerOptions {
    storage: TokenStore;
    refresh?: TokenRefreshHandler;
    autoRefresh?: boolean;
    refreshWindowMs?: number;
    clearOnRefreshError?: boolean;
    now?: () => number;
    fetch?: typeof globalThis.fetch;
    onRefreshError?: (error: unknown) => void;
}
```

#### `AuthxTokenManager`

```ts
export declare class AuthxTokenManager {
    constructor(options: AuthxTokenManagerOptions);
    start(): Promise<AuthxTokenSnapshot>;
    stop(): void;
    subscribe(listener: SnapshotListener): () => void;
    getSnapshot(): AuthxTokenSnapshot;
    setTokens(tokens: StoredTokenState | null): Promise<AuthxTokenSnapshot>;
    setTokenResponse(response: OidcTokenResponse, options?: SetTokenResponseOptions): Promise<AuthxTokenSnapshot>;
    clear(): Promise<AuthxTokenSnapshot>;
    getAccessToken(minValidityMs?: number): Promise<string | null>;
    refresh(): Promise<StoredTokenState>;
    fetch(input: RequestInfo | URL, init?: RequestInit, options?: AuthxFetchOptions): Promise<Response>;
}
```

#### `tokenResponseToStoredState`

```ts
export declare function tokenResponseToStoredState(response: OidcTokenResponse, options?: {
    now?: number;
    previous?: StoredTokenState | null;
    preserveRefreshToken?: boolean;
}): StoredTokenState;
```
