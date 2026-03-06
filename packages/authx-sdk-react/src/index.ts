import {
  createContext,
  createElement,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

import type {
  AuthxFetchOptions,
  AuthxTokenSnapshot,
  AuthxTokenManager,
  OidcTokenResponse,
  StoredTokenState,
} from "@authx/sdk-web";

export interface AuthxTokenProviderProps {
  client: AuthxTokenManager;
  children?: ReactNode;
}

export interface AuthxReactContextValue {
  client: AuthxTokenManager;
  snapshot: AuthxTokenSnapshot;
  accessToken: string | null;
  isAuthenticated: boolean;
  refresh(): Promise<StoredTokenState>;
  clear(): Promise<AuthxTokenSnapshot>;
  setTokens(tokens: StoredTokenState | null): Promise<AuthxTokenSnapshot>;
  setTokenResponse(
    response: OidcTokenResponse,
    options?: { now?: number; preserveRefreshToken?: boolean },
  ): Promise<AuthxTokenSnapshot>;
  fetch(input: RequestInfo | URL, init?: RequestInit, options?: AuthxFetchOptions): Promise<Response>;
}

const AuthxTokenContext = createContext<AuthxReactContextValue | null>(null);

export function AuthxTokenProvider(props: AuthxTokenProviderProps) {
  const { client, children } = props;
  const [snapshot, setSnapshot] = useState<AuthxTokenSnapshot>(() => client.getSnapshot());

  useEffect(() => {
    let active = true;

    void client.start().then((next) => {
      if (active) {
        setSnapshot(next);
      }
    });

    const unsubscribe = client.subscribe((next) => {
      if (active) {
        setSnapshot(next);
      }
    });

    return () => {
      active = false;
      unsubscribe();
    };
  }, [client]);

  const value: AuthxReactContextValue = {
    client,
    snapshot,
    accessToken: snapshot.tokens?.accessToken ?? null,
    isAuthenticated: snapshot.isAuthenticated,
    refresh: () => client.refresh(),
    clear: () => client.clear(),
    setTokens: (tokens) => client.setTokens(tokens),
    setTokenResponse: (response, options) => client.setTokenResponse(response, options),
    fetch: (input, init, options) => client.fetch(input, init, options),
  };

  return createElement(AuthxTokenContext.Provider, { value }, children);
}

export function useAuthxToken(): AuthxReactContextValue {
  const value = useContext(AuthxTokenContext);

  if (!value) {
    throw new Error("AuthxTokenProvider is missing from the React tree");
  }

  return value;
}

export function useAuthxSnapshot(): AuthxTokenSnapshot {
  return useAuthxToken().snapshot;
}

export function useAccessToken(): string | null {
  return useAuthxToken().accessToken;
}

export function useIsAuthenticated(): boolean {
  return useAuthxToken().isAuthenticated;
}

export function useAuthenticatedFetch() {
  return useAuthxToken().fetch;
}
