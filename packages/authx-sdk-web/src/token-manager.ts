import { AuthxTokenManagerError } from "./errors.js";
import type { TokenStore } from "./storage.js";

export interface OidcTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
  [key: string]: unknown;
}

export interface StoredTokenState {
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  refreshToken?: string;
  scope?: string;
  idToken?: string;
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

export interface SetTokenResponseOptions {
  now?: number;
  preserveRefreshToken?: boolean;
}

export type TokenRefreshHandler = (
  tokens: StoredTokenState,
) => Promise<OidcTokenResponse> | OidcTokenResponse;

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

type SnapshotListener = (snapshot: AuthxTokenSnapshot) => void;

export class AuthxTokenManager {
  private readonly storage: TokenStore;
  private readonly refreshHandler?: TokenRefreshHandler;
  private readonly autoRefresh: boolean;
  private readonly refreshWindowMs: number;
  private readonly clearOnRefreshError: boolean;
  private readonly now: () => number;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly onRefreshError?: (error: unknown) => void;
  private readonly listeners = new Set<SnapshotListener>();

  private current: StoredTokenState | null = null;
  private started = false;
  private refreshPromise?: Promise<StoredTokenState>;
  private refreshTimer?: ReturnType<typeof setTimeout>;
  private lastError?: unknown;

  constructor(options: AuthxTokenManagerOptions) {
    this.storage = options.storage;
    this.refreshHandler = options.refresh;
    this.autoRefresh = options.autoRefresh ?? true;
    this.refreshWindowMs = options.refreshWindowMs ?? 30_000;
    this.clearOnRefreshError = options.clearOnRefreshError ?? true;
    this.now = options.now ?? (() => Date.now());
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.onRefreshError = options.onRefreshError;
  }

  async start(): Promise<AuthxTokenSnapshot> {
    if (!this.started) {
      this.current = await this.storage.load();
      this.started = true;
      this.scheduleRefresh();
      this.emit();
    }

    return this.getSnapshot();
  }

  stop(): void {
    this.clearRefreshTimer();
  }

  subscribe(listener: SnapshotListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  getSnapshot(): AuthxTokenSnapshot {
    return {
      tokens: this.current ? { ...this.current } : null,
      isAuthenticated: Boolean(this.current?.accessToken),
      isRefreshing: Boolean(this.refreshPromise),
      error: this.lastError,
    };
  }

  async setTokens(tokens: StoredTokenState | null): Promise<AuthxTokenSnapshot> {
    await this.start();
    this.current = tokens ? { ...tokens } : null;
    this.lastError = undefined;
    await this.storage.save(this.current);
    this.scheduleRefresh();
    this.emit();
    return this.getSnapshot();
  }

  async setTokenResponse(
    response: OidcTokenResponse,
    options: SetTokenResponseOptions = {},
  ): Promise<AuthxTokenSnapshot> {
    return this.setTokens(
      tokenResponseToStoredState(response, {
        now: options.now ?? this.now(),
        previous: this.current,
        preserveRefreshToken: options.preserveRefreshToken,
      }),
    );
  }

  async clear(): Promise<AuthxTokenSnapshot> {
    return this.setTokens(null);
  }

  async getAccessToken(minValidityMs = 0): Promise<string | null> {
    await this.start();

    if (!this.current) {
      return null;
    }

    if (this.current.expiresAt <= this.now()) {
      if (!this.current.refreshToken || !this.refreshHandler) {
        await this.clear();
        return null;
      }

      return (await this.refresh()).accessToken;
    }

    if (this.expiresWithin(minValidityMs)) {
      if (!this.current.refreshToken || !this.refreshHandler) {
        return this.current.accessToken;
      }

      return (await this.refresh()).accessToken;
    }

    return this.current.accessToken;
  }

  async refresh(): Promise<StoredTokenState> {
    await this.start();

    if (!this.current?.refreshToken) {
      throw new AuthxTokenManagerError("refresh token is not available");
    }
    if (!this.refreshHandler) {
      throw new AuthxTokenManagerError("refresh handler is not configured");
    }
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    const refreshHandler = this.refreshHandler;
    const current = this.current;

    this.refreshPromise = (async () => {
      const response = await refreshHandler(current);
      const next = tokenResponseToStoredState(response, {
        now: this.now(),
        previous: current,
      });
      await this.setTokens(next);
      return next;
    })()
      .catch(async (error) => {
        this.lastError = error;
        this.onRefreshError?.(error);

        if (this.clearOnRefreshError) {
          await this.setTokens(null);
        } else {
          this.scheduleRefresh();
          this.emit();
        }

        throw error;
      })
      .finally(() => {
        this.refreshPromise = undefined;
        this.emit();
      });

    this.emit();
    return this.refreshPromise;
  }

  async fetch(
    input: RequestInfo | URL,
    init?: RequestInit,
    options: AuthxFetchOptions = {},
  ): Promise<Response> {
    await this.start();

    const request = new Request(input, init);
    const token = await this.getAccessToken(options.minValidityMs ?? this.refreshWindowMs);
    let response = await this.send(request.clone(), token);

    if (
      response.status === 401 &&
      (options.retryOnUnauthorized ?? true) &&
      this.current?.refreshToken &&
      this.refreshHandler
    ) {
      try {
        const refreshed = await this.refresh();
        response = await this.send(request.clone(), refreshed.accessToken);
      } catch {
        return response;
      }
    }

    return response;
  }

  private async send(request: Request, accessToken: string | null): Promise<Response> {
    const headers = new Headers(request.headers);

    if (accessToken && !headers.has("Authorization")) {
      headers.set("Authorization", `Bearer ${accessToken}`);
    }

    return this.fetchImpl(new Request(request, { headers }));
  }

  private expiresWithin(windowMs: number): boolean {
    if (!this.current) {
      return false;
    }

    return this.current.expiresAt - this.now() <= windowMs;
  }

  private scheduleRefresh(): void {
    this.clearRefreshTimer();

    if (
      !this.autoRefresh ||
      !this.current?.refreshToken ||
      !this.refreshHandler
    ) {
      return;
    }

    const delay = Math.max(this.current.expiresAt - this.now() - this.refreshWindowMs, 0);
    this.refreshTimer = setTimeout(() => {
      void this.refresh().catch(() => undefined);
    }, delay);
  }

  private clearRefreshTimer(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = undefined;
    }
  }

  private emit(): void {
    const snapshot = this.getSnapshot();
    for (const listener of this.listeners) {
      listener(snapshot);
    }
  }
}

export function tokenResponseToStoredState(
  response: OidcTokenResponse,
  options: {
    now?: number;
    previous?: StoredTokenState | null;
    preserveRefreshToken?: boolean;
  } = {},
): StoredTokenState {
  const now = options.now ?? Date.now();

  if (!response.access_token) {
    throw new AuthxTokenManagerError("access_token is required");
  }
  if (!response.token_type) {
    throw new AuthxTokenManagerError("token_type is required");
  }
  if (typeof response.expires_in !== "number" || !Number.isFinite(response.expires_in)) {
    throw new AuthxTokenManagerError("expires_in must be a finite number");
  }

  const refreshToken =
    response.refresh_token ??
    ((options.preserveRefreshToken ?? true) ? options.previous?.refreshToken : undefined);

  return {
    accessToken: response.access_token,
    tokenType: response.token_type,
    expiresAt: now + Math.max(response.expires_in, 0) * 1000,
    refreshToken,
    scope: response.scope,
    idToken: response.id_token,
  };
}
