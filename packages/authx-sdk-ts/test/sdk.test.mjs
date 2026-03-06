import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { existsSync } from "node:fs";
import test from "node:test";

import {
  BrowserSessionClient,
  buildAuthorizationUrl,
  createPkcePair,
  decodeJwtHeader,
  discoverIssuer,
  fetchIssuerJwks,
  fetchJwks,
  fetchUserInfo,
  getJwkForJwt,
  pollDeviceToken,
  randomState,
  refreshToken,
  revokeToken,
  selectJwk,
  startDeviceAuthorization,
} from "../dist/esm/index.js";

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

test("buildAuthorizationUrl includes PKCE and extra parameters", () => {
  const url = new URL(
    buildAuthorizationUrl({
      authorizationEndpoint: "https://issuer.example/authorize",
      clientId: "client-123",
      redirectUri: "https://app.example/callback",
      scope: "openid profile email",
      state: "state-123",
      nonce: "nonce-123",
      codeChallenge: "challenge-123",
      extraParams: {
        prompt: "login",
      },
    }),
  );

  assert.equal(url.searchParams.get("client_id"), "client-123");
  assert.equal(url.searchParams.get("redirect_uri"), "https://app.example/callback");
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("scope"), "openid profile email");
  assert.equal(url.searchParams.get("state"), "state-123");
  assert.equal(url.searchParams.get("nonce"), "nonce-123");
  assert.equal(url.searchParams.get("code_challenge"), "challenge-123");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("prompt"), "login");
});

test("PKCE helpers produce URL-safe values", async () => {
  const pair = await createPkcePair();
  const state = randomState();

  assert.match(pair.codeVerifier, /^[A-Za-z0-9\-_]+$/);
  assert.match(pair.codeChallenge, /^[A-Za-z0-9\-_]+$/);
  assert.equal(pair.codeChallengeMethod, "S256");
  assert.match(state, /^[A-Za-z0-9\-_]+$/);
});

test("OIDC and JWKS helpers send expected requests", async () => {
  const requests = [];
  globalThis.fetch = async (input, init = {}) => {
    requests.push({
      url: String(input),
      method: init.method ?? "GET",
      headers: init.headers ?? {},
      body: init.body instanceof URLSearchParams ? init.body.toString() : init.body,
    });

    if (String(input).includes(".well-known/openid-configuration")) {
      return jsonResponse({
        issuer: "https://issuer.example",
        authorization_endpoint: "https://issuer.example/authorize",
        token_endpoint: "https://issuer.example/token",
        jwks_uri: "https://issuer.example/jwks",
      });
    }

    if (String(input).endsWith("/jwks")) {
      return jsonResponse({
        keys: [
          {
            kid: "kid-1",
            kty: "RSA",
            alg: "RS256",
            use: "sig",
            n: "abc",
            e: "AQAB",
          },
        ],
      });
    }

    if (String(input).endsWith("/userinfo")) {
      return jsonResponse({ sub: "user-1", email: "alice@example.com" });
    }

    if (String(input).endsWith("/device_authorization")) {
      return jsonResponse({
        device_code: "device-code",
        user_code: "ABCD-EFGH",
        verification_uri: "https://issuer.example/device",
        expires_in: 600,
        interval: 5,
      });
    }

    if (String(input).endsWith("/token")) {
      return jsonResponse({
        access_token: "access-token",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "refresh-token",
      });
    }

    if (String(input).endsWith("/revoke")) {
      return new Response("", { status: 200 });
    }

    throw new Error(`unexpected request ${String(input)}`);
  };

  const discovery = await discoverIssuer("https://issuer.example");
  const directJwks = await fetchJwks("https://issuer.example/jwks");
  const issuerJwks = await fetchIssuerJwks("https://issuer.example");
  const refreshed = await refreshToken({
    tokenEndpoint: "https://issuer.example/token",
    clientId: "client-123",
    refreshToken: "refresh-token",
    scope: "openid profile",
  });
  const device = await startDeviceAuthorization({
    endpoint: "https://issuer.example/device_authorization",
    clientId: "client-123",
    scope: "openid",
  });
  const polled = await pollDeviceToken({
    tokenEndpoint: "https://issuer.example/token",
    clientId: "client-123",
    deviceCode: "device-code",
  });
  const userInfo = await fetchUserInfo("https://issuer.example/userinfo", "access-token");
  await revokeToken({
    revocationEndpoint: "https://issuer.example/revoke",
    clientId: "client-123",
    token: "refresh-token",
  });

  assert.equal(discovery.issuer, "https://issuer.example");
  assert.equal(directJwks.keys[0].kid, "kid-1");
  assert.equal(issuerJwks.keys[0].alg, "RS256");
  assert.equal(refreshed.access_token, "access-token");
  assert.equal(device.user_code, "ABCD-EFGH");
  assert.equal(polled.refresh_token, "refresh-token");
  assert.equal(userInfo.email, "alice@example.com");

  assert.equal(requests[0].url, "https://issuer.example/.well-known/openid-configuration");
  assert.equal(requests[1].url, "https://issuer.example/jwks");
  assert.equal(requests[2].url, "https://issuer.example/.well-known/openid-configuration");
  assert.equal(requests[3].url, "https://issuer.example/jwks");
  assert.match(requests[4].body, /grant_type=refresh_token/);
  assert.match(requests[5].body, /client_id=client-123/);
  assert.match(requests[6].body, /grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code/);
});

test("BrowserSessionClient uses credentials include and auth paths", async () => {
  const requests = [];
  globalThis.fetch = async (input, init = {}) => {
    requests.push({
      url: String(input),
      method: init.method ?? "GET",
      credentials: init.credentials,
      body: init.body,
    });

    if (String(input).endsWith("/auth/sign-in")) {
      return jsonResponse({
        user_id: "user-1",
        session_id: "session-1",
        token: "opaque-token",
      });
    }

    if (String(input).endsWith("/auth/session")) {
      return jsonResponse({
        user: { email: "alice@example.com" },
        session: { id: "session-1" },
      });
    }

    if (String(input).endsWith("/auth/sign-out")) {
      return new Response("", { status: 200 });
    }

    throw new Error(`unexpected request ${String(input)}`);
  };

  const client = new BrowserSessionClient({ baseUrl: "https://api.example.com" });
  const signIn = await client.signIn({
    email: "alice@example.com",
    password: "hunter2hunter2",
  });
  const session = await client.session();
  await client.signOut();

  assert.equal(signIn.session_id, "session-1");
  assert.equal(session.user?.email, "alice@example.com");
  assert.equal(requests[0].credentials, "include");
  assert.equal(requests[0].url, "https://api.example.com/auth/sign-in");
  assert.equal(requests[1].url, "https://api.example.com/auth/session");
});

test("JWKS helpers decode JWT headers and select the matching key", () => {
  const header = { alg: "RS256", kid: "kid-2", typ: "JWT" };
  const token = `${Buffer.from(JSON.stringify(header)).toString("base64url")}.payload.signature`;
  const jwks = {
    keys: [
      { kid: "kid-1", kty: "RSA", use: "sig", alg: "RS256", n: "a", e: "AQAB" },
      { kid: "kid-2", kty: "RSA", use: "sig", alg: "RS256", n: "b", e: "AQAB" },
    ],
  };

  const decodedHeader = decodeJwtHeader(token);
  const selected = selectJwk(jwks, { kid: "kid-2", use: "sig", alg: "RS256" });
  const selectedFromJwt = getJwkForJwt(jwks, token);

  assert.equal(decodedHeader.kid, "kid-2");
  assert.equal(selected?.kid, "kid-2");
  assert.equal(selectedFromJwt?.kid, "kid-2");
});

test("package build ships declarations and ESM output only", async () => {
  const esmSdk = await import("../dist/esm/index.js");

  assert.equal(typeof esmSdk.buildAuthorizationUrl, "function");
  assert.equal(typeof esmSdk.fetchJwks, "function");
  assert.equal(existsSync(new URL("../dist/types/index.d.ts", import.meta.url)), true);
  assert.equal(existsSync(new URL("../dist/cjs/index.js", import.meta.url)), false);
});

function jsonResponse(body, init = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}
