import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthxTokenManager,
  BrowserStorageTokenStore,
  MemoryTokenStore,
  createOidcTokenRefresher,
  tokenResponseToStoredState,
} from "../dist/esm/index.js";

test("tokenResponseToStoredState preserves refresh_token by default", () => {
  const tokens = tokenResponseToStoredState(
    {
      access_token: "next-access",
      token_type: "Bearer",
      expires_in: 60,
    },
    {
      now: 1_000,
      previous: {
        accessToken: "prev-access",
        tokenType: "Bearer",
        expiresAt: 2_000,
        refreshToken: "prev-refresh",
      },
    },
  );

  assert.equal(tokens.accessToken, "next-access");
  assert.equal(tokens.refreshToken, "prev-refresh");
  assert.equal(tokens.expiresAt, 61_000);
});

test("AuthxTokenManager refreshes expiring tokens and persists them", async () => {
  const store = new MemoryTokenStore({
    accessToken: "expired-access",
    tokenType: "Bearer",
    expiresAt: 500,
    refreshToken: "refresh-1",
  });

  let refreshCalls = 0;
  const client = new AuthxTokenManager({
    storage: store,
    autoRefresh: false,
    now: () => 1_000,
    refresh: async (current) => {
      refreshCalls += 1;
      assert.equal(current.refreshToken, "refresh-1");

      return {
        access_token: "fresh-access",
        token_type: "Bearer",
        expires_in: 120,
        refresh_token: "refresh-2",
      };
    },
  });

  const accessToken = await client.getAccessToken();
  const persisted = store.load();

  assert.equal(accessToken, "fresh-access");
  assert.equal(refreshCalls, 1);
  assert.equal(persisted?.accessToken, "fresh-access");
  assert.equal(persisted?.refreshToken, "refresh-2");
});

test("AuthxTokenManager fetch injects Authorization and retries after 401", async () => {
  const requests = [];
  let firstAttempt = true;

  const client = new AuthxTokenManager({
    storage: new MemoryTokenStore({
      accessToken: "access-1",
      tokenType: "Bearer",
      expiresAt: Date.now() + 60_000,
      refreshToken: "refresh-1",
    }),
    autoRefresh: false,
    fetch: async (input) => {
      const request = input instanceof Request ? input : new Request(input);
      requests.push(request.headers.get("Authorization"));

      if (firstAttempt) {
        firstAttempt = false;
        return new Response("expired", { status: 401 });
      }

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    },
    refresh: async () => ({
      access_token: "access-2",
      token_type: "Bearer",
      expires_in: 300,
      refresh_token: "refresh-2",
    }),
  });

  const response = await client.fetch("https://api.example.com/me");
  const body = await response.json();

  assert.deepEqual(requests, ["Bearer access-1", "Bearer access-2"]);
  assert.equal(body.ok, true);
});

test("createOidcTokenRefresher posts the expected form data", async () => {
  const requests = [];
  const refresh = createOidcTokenRefresher({
    tokenEndpoint: "https://issuer.example/token",
    clientId: "client-123",
    scope: "openid profile",
    fetch: async (input, init = {}) => {
      requests.push({
        url: String(input),
        method: init.method,
        body: init.body instanceof URLSearchParams ? init.body.toString() : String(init.body),
      });

      return new Response(
        JSON.stringify({
          access_token: "fresh-access",
          token_type: "Bearer",
          expires_in: 60,
          refresh_token: "fresh-refresh",
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      );
    },
  });

  const tokens = await refresh({
    accessToken: "old-access",
    tokenType: "Bearer",
    expiresAt: 1_000,
    refreshToken: "old-refresh",
  });

  assert.equal(tokens.refresh_token, "fresh-refresh");
  assert.equal(requests[0].url, "https://issuer.example/token");
  assert.match(requests[0].body, /grant_type=refresh_token/);
  assert.match(requests[0].body, /refresh_token=old-refresh/);
});

test("BrowserStorageTokenStore persists JSON payloads", () => {
  const storage = createMapStorage();
  const store = new BrowserStorageTokenStore({
    key: "custom-authx",
    storage,
  });

  store.save({
    accessToken: "access-1",
    tokenType: "Bearer",
    expiresAt: 123_456,
  });

  assert.equal(storage.getItem("custom-authx"), JSON.stringify(store.load()));
});

function createMapStorage() {
  const map = new Map();

  return {
    getItem(key) {
      return map.has(key) ? map.get(key) : null;
    },
    setItem(key, value) {
      map.set(key, value);
    },
    removeItem(key) {
      map.delete(key);
    },
  };
}
