import {
  computed,
  inject,
  onUnmounted,
  readonly,
  ref,
  type App,
  type InjectionKey,
} from "vue";

import type {
  AuthxFetchOptions,
  AuthxTokenManager,
  AuthxTokenSnapshot,
  OidcTokenResponse,
  StoredTokenState,
} from "@authx/sdk-web";

export interface AuthxVuePlugin {
  install(app: App): void;
}

export interface AuthxVueComposableResult {
  client: AuthxTokenManager;
  snapshot: Readonly<{ value: AuthxTokenSnapshot }>;
  accessToken: Readonly<{ value: string | null }>;
  isAuthenticated: Readonly<{ value: boolean }>;
  refresh(): Promise<StoredTokenState>;
  clear(): Promise<AuthxTokenSnapshot>;
  setTokens(tokens: StoredTokenState | null): Promise<AuthxTokenSnapshot>;
  setTokenResponse(
    response: OidcTokenResponse,
    options?: { now?: number; preserveRefreshToken?: boolean },
  ): Promise<AuthxTokenSnapshot>;
  fetch(input: RequestInfo | URL, init?: RequestInit, options?: AuthxFetchOptions): Promise<Response>;
}

export const AUTHX_TOKEN_KEY = Symbol("AuthxTokenManager") as InjectionKey<AuthxTokenManager>;

export function createAuthxPlugin(client: AuthxTokenManager): AuthxVuePlugin {
  return {
    install(app: App) {
      app.provide(AUTHX_TOKEN_KEY, client);
    },
  };
}

export function useAuthxToken(clientArg?: AuthxTokenManager): AuthxVueComposableResult {
  const client = clientArg ?? inject(AUTHX_TOKEN_KEY);

  if (!client) {
    throw new Error("AuthxTokenManager was not provided to the Vue app");
  }

  const snapshot = ref<AuthxTokenSnapshot>(client.getSnapshot());
  void client.start().then((next) => {
    snapshot.value = next;
  });

  const unsubscribe = client.subscribe((next) => {
    snapshot.value = next;
  });
  onUnmounted(unsubscribe);

  const accessToken = computed(() => snapshot.value.tokens?.accessToken ?? null);
  const isAuthenticated = computed(() => snapshot.value.isAuthenticated);

  return {
    client,
    snapshot: readonly(snapshot),
    accessToken,
    isAuthenticated,
    refresh: () => client.refresh(),
    clear: () => client.clear(),
    setTokens: (tokens) => client.setTokens(tokens),
    setTokenResponse: (response, options) => client.setTokenResponse(response, options),
    fetch: (input, init, options) => client.fetch(input, init, options),
  };
}
