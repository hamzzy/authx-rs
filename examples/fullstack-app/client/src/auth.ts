import {
  buildAuthorizationUrl,
  createPkcePair,
  discoverIssuer,
  exchangeAuthorizationCode,
  randomState,
} from "@authx-rs/sdk";
import {
  AuthxTokenManager,
  BrowserStorageTokenStore,
  createOidcTokenRefresher,
} from "@authx-rs/sdk-web";

const STORAGE_KEY = "authx.fullstack";
const STATE_KEY = `${STORAGE_KEY}.state`;
const VERIFIER_KEY = `${STORAGE_KEY}.verifier`;
const LAST_USER_ID_KEY = `${STORAGE_KEY}.last-user-id`;

const API_BASE = "";

export interface ExampleConfig {
  backendUrl: string;
  frontendUrl: string;
  oidcClientId: string;
  oidcIssuer: string;
  oidcRedirectUri: string;
  webauthnRpId: string;
  webauthnRpOrigin: string;
}

export interface ApiResult<T = unknown> {
  ok: boolean;
  status: number;
  data: T | null;
  text: string | null;
}

let configPromise: Promise<ExampleConfig> | null = null;

async function loadConfig(): Promise<ExampleConfig> {
  const fallbackIssuer = env("VITE_AUTHX_ISSUER") ?? window.location.origin;
  const fallbackRedirectUri = env("VITE_AUTHX_REDIRECT_URI") ?? window.location.origin;
  const fallbackClientId = env("VITE_AUTHX_CLIENT_ID");

  const res = await fetch(`${API_BASE}/debug/config`, {
    credentials: "same-origin",
  }).catch(() => null);

  if (res?.ok) {
    const data = (await res.json()) as Record<string, string>;
    return {
      backendUrl: data.backend_url ?? "http://localhost:4000",
      frontendUrl: data.frontend_url ?? window.location.origin,
      oidcClientId: data.oidc_client_id ?? required("VITE_AUTHX_CLIENT_ID", fallbackClientId),
      oidcIssuer: data.oidc_issuer ?? fallbackIssuer,
      oidcRedirectUri: data.oidc_redirect_uri ?? fallbackRedirectUri,
      webauthnRpId: data.webauthn_rp_id ?? "localhost",
      webauthnRpOrigin: data.webauthn_rp_origin ?? window.location.origin,
    };
  }

  return {
    backendUrl: "http://localhost:4000",
    frontendUrl: window.location.origin,
    oidcClientId: required("VITE_AUTHX_CLIENT_ID", fallbackClientId),
    oidcIssuer: fallbackIssuer,
    oidcRedirectUri: fallbackRedirectUri,
    webauthnRpId: "localhost",
    webauthnRpOrigin: window.location.origin,
  };
}

export function getExampleConfig(): Promise<ExampleConfig> {
  configPromise ??= loadConfig();
  return configPromise;
}

const refreshOidcTokens = async (tokens: {
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  refreshToken?: string;
  scope?: string;
  idToken?: string;
}) => {
  const config = await getExampleConfig();
  return createOidcTokenRefresher({
    tokenEndpoint: `${config.oidcIssuer}/oidc/token`,
    clientId: config.oidcClientId,
  })(tokens);
};

export const tokenManager = new AuthxTokenManager({
  storage: new BrowserStorageTokenStore({ key: `${STORAGE_KEY}.tokens` }),
  refresh: refreshOidcTokens,
});

/** Redirect the browser to the OIDC authorize endpoint (PKCE). */
export async function startOidcLogin(): Promise<void> {
  const config = await getExampleConfig();
  const discovery = await discoverIssuer(config.oidcIssuer);
  const pkce = await createPkcePair();
  const state = randomState();

  sessionStorage.setItem(STATE_KEY, state);
  sessionStorage.setItem(VERIFIER_KEY, pkce.codeVerifier);

  window.location.assign(
    buildAuthorizationUrl({
      authorizationEndpoint: discovery.authorization_endpoint,
      clientId: config.oidcClientId,
      redirectUri: config.oidcRedirectUri,
      scope: "openid profile email offline_access",
      state,
      codeChallenge: pkce.codeChallenge,
    }),
  );
}

/** Complete the OIDC callback — exchange code for tokens. */
export async function completeLoginFromCallback(): Promise<boolean> {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return false;
  }

  const expectedState = sessionStorage.getItem(STATE_KEY);
  const codeVerifier = sessionStorage.getItem(VERIFIER_KEY);
  if (!expectedState || state !== expectedState || !codeVerifier) {
    throw new Error("OIDC callback validation failed");
  }

  const config = await getExampleConfig();
  const discovery = await discoverIssuer(config.oidcIssuer);
  const tokens = await exchangeAuthorizationCode({
    tokenEndpoint: discovery.token_endpoint,
    clientId: config.oidcClientId,
    code,
    redirectUri: config.oidcRedirectUri,
    codeVerifier,
  });

  await tokenManager.setTokenResponse(tokens);

  sessionStorage.removeItem(STATE_KEY);
  sessionStorage.removeItem(VERIFIER_KEY);
  window.history.replaceState({}, document.title, config.oidcRedirectUri);
  return true;
}

function defaultHeaders(init?: HeadersInit): Headers {
  const headers = new Headers(init);
  if (!headers.has("Origin")) {
    headers.set("Origin", window.location.origin);
  }
  return headers;
}

async function readResult<T>(res: Response): Promise<ApiResult<T>> {
  const text = await res.text();
  let data: T | null = null;

  if (text) {
    try {
      data = JSON.parse(text) as T;
    } catch {
      data = null;
    }
  }

  return {
    ok: res.ok,
    status: res.status,
    data,
    text: text || null,
  };
}

async function request<T>(path: string, init?: RequestInit): Promise<ApiResult<T>> {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: "same-origin",
    ...init,
  });
  return readResult<T>(res);
}

async function apiPost<T>(path: string, body: Record<string, unknown>) {
  return request<T>(path, {
    method: "POST",
    headers: defaultHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
}

async function apiForm<T>(path: string, body: Record<string, string>) {
  return request<T>(path, {
    method: "POST",
    headers: defaultHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
    body: new URLSearchParams(body),
  });
}

async function apiGet<T>(path: string) {
  return request<T>(path);
}

async function apiDelete<T>(path: string) {
  return request<T>(path, {
    method: "DELETE",
  });
}

export async function discoverExampleIssuer() {
  const config = await getExampleConfig();
  return discoverIssuer(config.oidcIssuer);
}

export function rememberUserId(userId: string | null | undefined) {
  if (!userId) {
    return;
  }
  localStorage.setItem(LAST_USER_ID_KEY, userId);
}

export function getRememberedUserId(): string {
  return localStorage.getItem(LAST_USER_ID_KEY) ?? "";
}

export async function setSessionCookieFromToken(token: string) {
  return apiPost<{ ok: boolean }>("/auth/debug/session-cookie", { token });
}

export const api = {
  get: apiGet,
  post: apiPost,
  postForm: apiForm,
  delete: apiDelete,
  request,
};

function env(name: "VITE_AUTHX_ISSUER" | "VITE_AUTHX_CLIENT_ID" | "VITE_AUTHX_REDIRECT_URI") {
  const value = import.meta.env[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function required(name: string, value: string | undefined) {
  if (!value) {
    throw new Error(`${name} is required — check client/.env or /debug/config`);
  }
  return value;
}
