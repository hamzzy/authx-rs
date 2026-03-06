---
title: "@authx/sdk"
description: "Generated API reference for @authx/sdk."
---

Generated from `packages/authx-sdk-ts/dist/types`.

Low-level OIDC, JWKS, PKCE, device, and browser-session helpers.

## Modules

- [`device`](#device)
- [`errors`](#errors)
- [`jwks`](#jwks)
- [`oidc`](#oidc)
- [`pkce`](#pkce)
- [`session`](#session)

### device

#### `DeviceAuthorizationResponse`

```ts
export interface DeviceAuthorizationResponse {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete?: string;
    expires_in: number;
    interval: number;
    [key: string]: unknown;
}
```

#### `DeviceAuthorizationOptions`

```ts
export interface DeviceAuthorizationOptions {
    endpoint: string;
    clientId: string;
    scope?: string;
}
```

#### `PollDeviceTokenOptions`

```ts
export interface PollDeviceTokenOptions {
    tokenEndpoint: string;
    clientId: string;
    deviceCode: string;
    clientSecret?: string;
}
```

#### `startDeviceAuthorization`

```ts
export declare function startDeviceAuthorization(options: DeviceAuthorizationOptions): Promise<DeviceAuthorizationResponse>;
```

#### `pollDeviceToken`

```ts
export declare function pollDeviceToken(options: PollDeviceTokenOptions): Promise<OidcTokenResponse>;
```

### errors

#### `AuthxErrorBody`

```ts
export interface AuthxErrorBody {
    error?: string;
    message?: string;
    error_description?: string;
    [key: string]: unknown;
}
```

#### `AuthxSdkError`

```ts
export declare class AuthxSdkError extends Error {
    readonly status?: number;
    readonly code?: string;
    readonly details?: unknown;
    constructor(message: string, options?: {
        status?: number;
        code?: string;
        details?: unknown;
    });
}
```

#### `toAuthxSdkError`

```ts
export declare function toAuthxSdkError(message: string, options?: {
    status?: number;
    code?: string;
    details?: unknown;
}): AuthxSdkError;
```

### jwks

#### `JwtHeader`

```ts
export interface JwtHeader {
    alg?: string;
    typ?: string;
    kid?: string;
    [key: string]: unknown;
}
```

#### `OidcJwk`

```ts
export interface OidcJwk extends JsonWebKey {
    kid?: string;
    use?: string;
    alg?: string;
    kty: string;
    x5c?: string[];
    [key: string]: unknown;
}
```

#### `JwksDocument`

```ts
export interface JwksDocument {
    keys: OidcJwk[];
    [key: string]: unknown;
}
```

#### `SelectJwkOptions`

```ts
export interface SelectJwkOptions {
    kid?: string;
    alg?: string;
    use?: string;
    kty?: string;
}
```

#### `fetchJwks`

```ts
export declare function fetchJwks(jwksUri: string): Promise<JwksDocument>;
```

#### `fetchIssuerJwks`

```ts
export declare function fetchIssuerJwks(issuer: string): Promise<JwksDocument>;
```

#### `decodeJwtHeader`

```ts
export declare function decodeJwtHeader(token: string): JwtHeader;
```

#### `selectJwk`

```ts
export declare function selectJwk(jwks: JwksDocument, options: SelectJwkOptions): OidcJwk | undefined;
```

#### `getJwkForJwt`

```ts
export declare function getJwkForJwt(jwks: JwksDocument, token: string): OidcJwk | undefined;
```

### oidc

#### `OidcDiscoveryDocument`

```ts
export interface OidcDiscoveryDocument {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint?: string;
    jwks_uri?: string;
    revocation_endpoint?: string;
    introspection_endpoint?: string;
    device_authorization_endpoint?: string;
    token_endpoint_auth_methods_supported?: string[];
    response_types_supported?: string[];
    grant_types_supported?: string[];
    scopes_supported?: string[];
    id_token_signing_alg_values_supported?: string[];
    [key: string]: unknown;
}
```

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

#### `IntrospectionResponse`

```ts
export interface IntrospectionResponse {
    active: boolean;
    scope?: string;
    client_id?: string;
    username?: string;
    token_type?: string;
    exp?: number;
    iat?: number;
    sub?: string;
    iss?: string;
    [key: string]: unknown;
}
```

#### `BuildAuthorizationUrlOptions`

```ts
export interface BuildAuthorizationUrlOptions {
    authorizationEndpoint: string;
    clientId: string;
    redirectUri: string;
    scope?: string;
    state?: string;
    nonce?: string;
    codeChallenge?: string;
    codeChallengeMethod?: "S256";
    extraParams?: Record<string, string | undefined>;
}
```

#### `ExchangeCodeOptions`

```ts
export interface ExchangeCodeOptions {
    tokenEndpoint: string;
    clientId: string;
    code: string;
    redirectUri: string;
    codeVerifier?: string;
    clientSecret?: string;
}
```

#### `RefreshTokenOptions`

```ts
export interface RefreshTokenOptions {
    tokenEndpoint: string;
    clientId: string;
    refreshToken: string;
    scope?: string;
    clientSecret?: string;
}
```

#### `RevokeTokenOptions`

```ts
export interface RevokeTokenOptions {
    revocationEndpoint: string;
    clientId: string;
    token: string;
    tokenTypeHint?: string;
    clientSecret?: string;
}
```

#### `IntrospectTokenOptions`

```ts
export interface IntrospectTokenOptions {
    introspectionEndpoint: string;
    clientId: string;
    token: string;
    tokenTypeHint?: string;
    clientSecret?: string;
}
```

#### `UserInfoClaims`

```ts
export interface UserInfoClaims {
    sub: string;
    email?: string;
    email_verified?: boolean;
    preferred_username?: string;
    [key: string]: unknown;
}
```

#### `discoverIssuer`

```ts
export declare function discoverIssuer(issuer: string): Promise<OidcDiscoveryDocument>;
```

#### `buildAuthorizationUrl`

```ts
export declare function buildAuthorizationUrl(options: BuildAuthorizationUrlOptions): string;
```

#### `exchangeAuthorizationCode`

```ts
export declare function exchangeAuthorizationCode(options: ExchangeCodeOptions): Promise<OidcTokenResponse>;
```

#### `refreshToken`

```ts
export declare function refreshToken(options: RefreshTokenOptions): Promise<OidcTokenResponse>;
```

#### `revokeToken`

```ts
export declare function revokeToken(options: RevokeTokenOptions): Promise<void>;
```

#### `introspectToken`

```ts
export declare function introspectToken(options: IntrospectTokenOptions): Promise<IntrospectionResponse>;
```

#### `fetchUserInfo`

```ts
export declare function fetchUserInfo(userInfoEndpoint: string, accessToken: string): Promise<UserInfoClaims>;
```

### pkce

#### `PkcePair`

```ts
export interface PkcePair {
    codeVerifier: string;
    codeChallenge: string;
    codeChallengeMethod: "S256";
}
```

#### `randomString`

```ts
export declare function randomString(byteLength?: number): string;
```

#### `createPkcePair`

```ts
export declare function createPkcePair(byteLength?: number): Promise<PkcePair>;
```

#### `randomState`

```ts
export declare function randomState(byteLength?: number): string;
```

### session

#### `SessionUser`

```ts
export interface SessionUser {
    id?: string;
    user_id?: string;
    email?: string;
    email_verified?: boolean;
    username?: string | null;
    [key: string]: unknown;
}
```

#### `SessionRecord`

```ts
export interface SessionRecord {
    id?: string;
    session_id?: string;
    user_id?: string;
    ip_address?: string;
    org_id?: string | null;
    expires_at?: string;
    created_at?: string;
    [key: string]: unknown;
}
```

#### `SignInResult`

```ts
export interface SignInResult {
    user_id: string;
    session_id: string;
    token: string;
    [key: string]: unknown;
}
```

#### `SignUpResult`

```ts
export interface SignUpResult {
    user_id: string;
    email: string;
    [key: string]: unknown;
}
```

#### `SessionEnvelope`

```ts
export interface SessionEnvelope {
    user?: SessionUser;
    session?: SessionRecord;
    [key: string]: unknown;
}
```

#### `BrowserSessionClientOptions`

```ts
export interface BrowserSessionClientOptions {
    baseUrl: string;
    credentials?: RequestCredentials;
    headers?: HeadersInit;
}
```

#### `CredentialInput`

```ts
export interface CredentialInput {
    email: string;
    password: string;
}
```

#### `BrowserSessionClient`

```ts
export declare class BrowserSessionClient {
    constructor(options: BrowserSessionClientOptions);
    signUp(body: CredentialInput): Promise<SignUpResult>;
    signIn(body: CredentialInput): Promise<SignInResult>;
    signOut(): Promise<void>;
    signOutAll(): Promise<void>;
    session(): Promise<SessionEnvelope>;
    sessions(): Promise<SessionRecord[]>;
}
```
