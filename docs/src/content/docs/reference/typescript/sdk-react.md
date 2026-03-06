---
title: "@authx/sdk-react"
description: "Generated API reference for @authx/sdk-react."
---

Generated from `packages/authx-sdk-react/dist/types`.

React provider and hooks for authx token clients.

## Modules

- [`index`](#index)

### index

#### `AuthxTokenProviderProps`

```ts
export interface AuthxTokenProviderProps {
    client: AuthxTokenManager;
    children?: ReactNode;
}
```

#### `AuthxReactContextValue`

```ts
export interface AuthxReactContextValue {
    client: AuthxTokenManager;
    snapshot: AuthxTokenSnapshot;
    accessToken: string | null;
    isAuthenticated: boolean;
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

#### `AuthxTokenProvider`

```ts
export declare function AuthxTokenProvider(props: AuthxTokenProviderProps): ReactElement;
```

#### `useAuthxToken`

```ts
export declare function useAuthxToken(): AuthxReactContextValue;
```

#### `useAuthxSnapshot`

```ts
export declare function useAuthxSnapshot(): AuthxTokenSnapshot;
```

#### `useAccessToken`

```ts
export declare function useAccessToken(): string | null;
```

#### `useIsAuthenticated`

```ts
export declare function useIsAuthenticated(): boolean;
```

#### `useAuthenticatedFetch`

```ts
export declare function useAuthenticatedFetch(): (input: RequestInfo | URL, init?: RequestInit, options?: AuthxFetchOptions) => Promise<Response>;
```
