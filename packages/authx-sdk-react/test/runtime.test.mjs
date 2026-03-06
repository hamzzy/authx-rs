import assert from "node:assert/strict";
import test from "node:test";

import React from "react";
import { act, render, waitFor } from "@testing-library/react";
import { JSDOM } from "jsdom";

import { MemoryTokenStore, AuthxTokenManager } from "../../authx-sdk-web/src/index.js";
import {
  AuthxTokenProvider,
  useAccessToken,
  useAuthxSnapshot,
  useIsAuthenticated,
} from "../dist/esm/index.js";

test("React provider exposes snapshot updates from the token manager", async () => {
  const cleanupDom = installDom();
  try {
    const client = new AuthxTokenManager({
      storage: new MemoryTokenStore({
        accessToken: "initial-access",
        tokenType: "Bearer",
        expiresAt: Date.now() + 60_000,
      }),
      autoRefresh: false,
    });

    function Probe() {
      const accessToken = useAccessToken();
      const snapshot = useAuthxSnapshot();
      const isAuthenticated = useIsAuthenticated();

      return React.createElement(
        "div",
        {
          "data-access-token": accessToken ?? "",
          "data-authenticated": String(isAuthenticated),
          "data-refreshing": String(snapshot.isRefreshing),
        },
        accessToken ?? "",
      );
    }

    let view;
    await act(async () => {
      view = render(
        React.createElement(
          AuthxTokenProvider,
          { client },
          React.createElement(Probe),
        ),
      );
    });

    await waitFor(() => {
      assert.equal(
        view.container.firstChild?.getAttribute("data-access-token"),
        "initial-access",
      );
    });

    await act(async () => {
      await client.setTokens({
        accessToken: "updated-access",
        tokenType: "Bearer",
        expiresAt: Date.now() + 60_000,
      });
    });

    await waitFor(() => {
      assert.equal(
        view.container.firstChild?.getAttribute("data-access-token"),
        "updated-access",
      );
      assert.equal(
        view.container.firstChild?.getAttribute("data-authenticated"),
        "true",
      );
    });

    view.unmount();
  } finally {
    cleanupDom();
  }
});

function installDom() {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", {
    url: "https://app.example.com",
  });

  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  globalThis.navigator = dom.window.navigator;
  globalThis.HTMLElement = dom.window.HTMLElement;
  globalThis.Node = dom.window.Node;
  globalThis.Event = dom.window.Event;
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;

  return () => {
    dom.window.close();
    delete globalThis.window;
    delete globalThis.document;
    delete globalThis.navigator;
    delete globalThis.HTMLElement;
    delete globalThis.Node;
    delete globalThis.Event;
    delete globalThis.IS_REACT_ACT_ENVIRONMENT;
  };
}
