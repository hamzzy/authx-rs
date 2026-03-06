---
title: "@authx-rs/sdk-vue"
description: "Generated API reference for @authx-rs/sdk-vue."
---

Generated from `packages/authx-sdk-vue/dist/types`.

Vue plugin and composable for authx token clients.

## Modules

- [`index`](#index)

### index

#### `AuthxVuePlugin`

```ts
export interface AuthxVuePlugin {
    install(app: App): void;
}
```

#### `AuthxVueComposableResult`

```ts
export interface AuthxVueComposableResult {
    client: AuthxTokenManager;
    snapshot: Readonly<{
        value: AuthxTokenSnapshot;
    }>;
    accessToken: Readonly<{
        value: string | null;
    }>;
    isAuthenticated: Readonly<{
        value: boolean;
    }>;
    refresh(): Promise<StoredTokenState>;
    clear(): Promise<AuthxTokenSnapshot>;
    setTokens(tokens: StoredTokenState | null): Promise<AuthxTokenSnapshot>;
    setTokenResponse(response: OidcTokenResponse, options?: {
        now?: number;
        preserveRefreshToken?: boolean;
    }): Promise<AuthxTokenSnapshot>;
    fetch(input: RequestInfo | URL, init?: RequestInit, options?: AuthxFetchOptions): Promise<Response>;
}
```

#### `AUTHX_TOKEN_KEY`

```ts
export declare const AUTHX_TOKEN_KEY: InjectionKey<AuthxTokenManager>;
```

#### `createAuthxPlugin`

```ts
export declare function createAuthxPlugin(client: AuthxTokenManager): AuthxVuePlugin;
```

#### `useAuthxToken`

```ts
export declare function useAuthxToken(clientArg?: AuthxTokenManager): AuthxVueComposableResult;
```
