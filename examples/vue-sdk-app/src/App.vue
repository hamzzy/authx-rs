<script setup lang="ts">
import { onMounted, ref } from "vue";

import { useAuthxToken } from "@authx-rs/sdk-vue";

import { completeLoginFromCallback, startLogin, tokenManager } from "./auth";

const auth = useAuthxToken();
const status = ref("idle");
const error = ref<string | null>(null);
const ready = ref(false);

onMounted(async () => {
  try {
    await tokenManager.start();
    await completeLoginFromCallback();
  } catch (cause) {
    error.value = String(cause);
  } finally {
    ready.value = true;
  }
});

async function clearTokens() {
  await tokenManager.clear();
  status.value = "tokens cleared";
}

async function testAuthenticatedFetch() {
  try {
    await auth.fetch("https://httpbin.org/headers");
    status.value = "authenticated fetch completed";
  } catch (cause) {
    status.value = String(cause);
  }
}
</script>

<template>
  <main style="font-family: ui-sans-serif, system-ui; margin: 3rem auto; max-width: 720px">
    <h1>authx Vue SDK Example</h1>
    <p v-if="!ready">Loading auth state...</p>
    <p v-else-if="error">{{ error }}</p>
    <template v-else>
      <p>
        This example uses <code>@authx-rs/sdk</code>, <code>@authx-rs/sdk-web</code>, and
        <code>@authx-rs/sdk-vue</code>.
      </p>
      <p>Status: {{ auth.isAuthenticated.value ? "authenticated" : "signed out" }}</p>
      <p>
        Access token:
        {{ auth.accessToken.value ? `${auth.accessToken.value.slice(0, 16)}...` : "none" }}
      </p>
      <div style="display: flex; gap: 0.75rem; flex-wrap: wrap">
        <button @click="startLogin">Start OIDC Login</button>
        <button @click="clearTokens">Clear Tokens</button>
        <button @click="testAuthenticatedFetch">Test Authenticated Fetch</button>
      </div>
      <p>{{ status }}</p>
    </template>
  </main>
</template>
