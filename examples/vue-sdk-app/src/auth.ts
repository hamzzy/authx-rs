import {
  buildAuthorizationUrl,
  createPkcePair,
  discoverIssuer,
  exchangeAuthorizationCode,
  randomState,
} from "@authx/sdk";
import {
  AuthxTokenManager,
  BrowserStorageTokenStore,
  createOidcTokenRefresher,
} from "@authx/sdk-web";

const STORAGE_KEY = "authx.vue.example";
const STATE_KEY = `${STORAGE_KEY}.state`;
const VERIFIER_KEY = `${STORAGE_KEY}.verifier`;

const issuer = env("VITE_AUTHX_ISSUER");
const clientId = env("VITE_AUTHX_CLIENT_ID");
const redirectUri = env("VITE_AUTHX_REDIRECT_URI");

export const tokenManager = new AuthxTokenManager({
  storage: new BrowserStorageTokenStore({ key: `${STORAGE_KEY}.tokens` }),
  refresh: createOidcTokenRefresher({
    tokenEndpoint: `${issuer}/oidc/token`,
    clientId,
  }),
});

export async function startLogin(): Promise<void> {
  const discovery = await discoverIssuer(issuer);
  const pkce = await createPkcePair();
  const state = randomState();

  sessionStorage.setItem(STATE_KEY, state);
  sessionStorage.setItem(VERIFIER_KEY, pkce.codeVerifier);

  window.location.assign(
    buildAuthorizationUrl({
      authorizationEndpoint: discovery.authorization_endpoint,
      clientId,
      redirectUri,
      scope: "openid profile email offline_access",
      state,
      codeChallenge: pkce.codeChallenge,
    }),
  );
}

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

  const discovery = await discoverIssuer(issuer);
  const tokens = await exchangeAuthorizationCode({
    tokenEndpoint: discovery.token_endpoint,
    clientId,
    code,
    redirectUri,
    codeVerifier,
  });

  await tokenManager.setTokenResponse(tokens);

  sessionStorage.removeItem(STATE_KEY);
  sessionStorage.removeItem(VERIFIER_KEY);
  window.history.replaceState({}, document.title, redirectUri);
  return true;
}

function env(name: "VITE_AUTHX_ISSUER" | "VITE_AUTHX_CLIENT_ID" | "VITE_AUTHX_REDIRECT_URI") {
  const value = import.meta.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}
