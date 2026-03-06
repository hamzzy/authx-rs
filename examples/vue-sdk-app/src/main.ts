import { createApp } from "vue";

import { createAuthxPlugin } from "@authx/sdk-vue";

import App from "./App.vue";
import { tokenManager } from "./auth";

createApp(App).use(createAuthxPlugin(tokenManager)).mount("#app");
