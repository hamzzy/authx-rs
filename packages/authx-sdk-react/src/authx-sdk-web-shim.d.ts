declare module "@authx/sdk-web" {
  export interface StoredTokenState {
    accessToken: string;
    tokenType: string;
    expiresAt: number;
    refreshToken?: string;
    scope?: string;
    idToken?: string;
    [key: string]: unknown;
  }

  export interface OidcTokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
    [key: string]: unknown;
  }

  export interface AuthxTokenSnapshot {
    tokens: StoredTokenState | null;
    isAuthenticated: boolean;
    isRefreshing: boolean;
    error?: unknown;
  }

  export interface AuthxFetchOptions {
    minValidityMs?: number;
    retryOnUnauthorized?: boolean;
  }

  export class AuthxTokenManager {
    start(): Promise<AuthxTokenSnapshot>;
    subscribe(listener: (snapshot: AuthxTokenSnapshot) => void): () => void;
    getSnapshot(): AuthxTokenSnapshot;
    refresh(): Promise<StoredTokenState>;
    clear(): Promise<AuthxTokenSnapshot>;
    setTokens(tokens: StoredTokenState | null): Promise<AuthxTokenSnapshot>;
    setTokenResponse(
      response: OidcTokenResponse,
      options?: { now?: number; preserveRefreshToken?: boolean },
    ): Promise<AuthxTokenSnapshot>;
    fetch(input: RequestInfo | URL, init?: RequestInit, options?: AuthxFetchOptions): Promise<Response>;
  }
}
