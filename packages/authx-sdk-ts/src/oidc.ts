import { requestJson } from "./http.js";

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

export interface OidcTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
  [key: string]: unknown;
}

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

export interface ExchangeCodeOptions {
  tokenEndpoint: string;
  clientId: string;
  code: string;
  redirectUri: string;
  codeVerifier?: string;
  clientSecret?: string;
}

export interface RefreshTokenOptions {
  tokenEndpoint: string;
  clientId: string;
  refreshToken: string;
  scope?: string;
  clientSecret?: string;
}

export interface RevokeTokenOptions {
  revocationEndpoint: string;
  clientId: string;
  token: string;
  tokenTypeHint?: string;
  clientSecret?: string;
}

export interface IntrospectTokenOptions {
  introspectionEndpoint: string;
  clientId: string;
  token: string;
  tokenTypeHint?: string;
  clientSecret?: string;
}

export interface UserInfoClaims {
  sub: string;
  email?: string;
  email_verified?: boolean;
  preferred_username?: string;
  [key: string]: unknown;
}

export async function discoverIssuer(issuer: string): Promise<OidcDiscoveryDocument> {
  const base = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer;
  return requestJson<OidcDiscoveryDocument>({
    path: `${base}/.well-known/openid-configuration`,
    method: "GET",
  });
}

export function buildAuthorizationUrl(options: BuildAuthorizationUrlOptions): string {
  const url = new URL(options.authorizationEndpoint);

  url.searchParams.set("client_id", options.clientId);
  url.searchParams.set("redirect_uri", options.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", options.scope ?? "openid");

  if (options.state) {
    url.searchParams.set("state", options.state);
  }
  if (options.nonce) {
    url.searchParams.set("nonce", options.nonce);
  }
  if (options.codeChallenge) {
    url.searchParams.set("code_challenge", options.codeChallenge);
    url.searchParams.set("code_challenge_method", options.codeChallengeMethod ?? "S256");
  }

  for (const [key, value] of Object.entries(options.extraParams ?? {})) {
    if (value !== undefined) {
      url.searchParams.set(key, value);
    }
  }

  return url.toString();
}

export async function exchangeAuthorizationCode(
  options: ExchangeCodeOptions,
): Promise<OidcTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: options.clientId,
    code: options.code,
    redirect_uri: options.redirectUri,
  });

  if (options.clientSecret) {
    body.set("client_secret", options.clientSecret);
  }
  if (options.codeVerifier) {
    body.set("code_verifier", options.codeVerifier);
  }

  return requestJson<OidcTokenResponse>({
    path: options.tokenEndpoint,
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
}

export async function refreshToken(options: RefreshTokenOptions): Promise<OidcTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: options.clientId,
    refresh_token: options.refreshToken,
  });

  if (options.scope) {
    body.set("scope", options.scope);
  }
  if (options.clientSecret) {
    body.set("client_secret", options.clientSecret);
  }

  return requestJson<OidcTokenResponse>({
    path: options.tokenEndpoint,
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
}

export async function revokeToken(options: RevokeTokenOptions): Promise<void> {
  const body = new URLSearchParams({
    client_id: options.clientId,
    token: options.token,
  });

  if (options.clientSecret) {
    body.set("client_secret", options.clientSecret);
  }
  if (options.tokenTypeHint) {
    body.set("token_type_hint", options.tokenTypeHint);
  }

  await requestJson<unknown>({
    path: options.revocationEndpoint,
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  }).catch(async (error) => {
    // RFC 7009 often uses empty 200 responses. Swallow only the success-case parse issue.
    if (error instanceof Error && /unexpected end of json/i.test(error.message)) {
      return;
    }
    throw error;
  });
}

export async function introspectToken(
  options: IntrospectTokenOptions,
): Promise<IntrospectionResponse> {
  const body = new URLSearchParams({
    client_id: options.clientId,
    token: options.token,
  });

  if (options.clientSecret) {
    body.set("client_secret", options.clientSecret);
  }
  if (options.tokenTypeHint) {
    body.set("token_type_hint", options.tokenTypeHint);
  }

  return requestJson<IntrospectionResponse>({
    path: options.introspectionEndpoint,
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
}

export async function fetchUserInfo(
  userInfoEndpoint: string,
  accessToken: string,
): Promise<UserInfoClaims> {
  return requestJson<UserInfoClaims>({
    path: userInfoEndpoint,
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });
}
