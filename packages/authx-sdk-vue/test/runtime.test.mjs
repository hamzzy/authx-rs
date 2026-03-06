import assert from "node:assert/strict";
import test from "node:test";

import { JSDOM } from "jsdom";

test("Vue plugin provides a reactive authx token composable", async () => {
  const cleanupDom = installDom();
  try {
    const { defineComponent, h, nextTick } = await import("vue");
    const { mount } = await import("@vue/test-utils");
    const { MemoryTokenStore, AuthxTokenManager } = await import("../../authx-sdk-web/src/index.js");
    const { createAuthxPlugin, useAuthxToken } = await import("../dist/esm/index.js");

    const client = new AuthxTokenManager({
      storage: new MemoryTokenStore({
        accessToken: "initial-access",
        tokenType: "Bearer",
        expiresAt: Date.now() + 60_000,
      }),
      autoRefresh: false,
    });

    const Probe = defineComponent({
      setup() {
        const auth = useAuthxToken();
        return () =>
          h("div", {
            "data-access-token": auth.accessToken.value ?? "",
            "data-authenticated": String(auth.isAuthenticated.value),
          });
      },
    });

    const wrapper = mount(Probe, {
      global: {
        plugins: [createAuthxPlugin(client)],
      },
    });

    await nextTick();
    assert.equal(wrapper.attributes("data-access-token"), "initial-access");
    assert.equal(wrapper.attributes("data-authenticated"), "true");

    await client.setTokens({
      accessToken: "updated-access",
      tokenType: "Bearer",
      expiresAt: Date.now() + 60_000,
    });

    await nextTick();
    assert.equal(wrapper.attributes("data-access-token"), "updated-access");

    wrapper.unmount();
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
  globalThis.Element = dom.window.Element;
  globalThis.Node = dom.window.Node;
  globalThis.SVGElement = dom.window.SVGElement;

  return () => {
    dom.window.close();
    delete globalThis.window;
    delete globalThis.document;
    delete globalThis.navigator;
    delete globalThis.HTMLElement;
    delete globalThis.Element;
    delete globalThis.Node;
    delete globalThis.SVGElement;
  };
}
