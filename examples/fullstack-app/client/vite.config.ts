import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/auth": "http://127.0.0.1:4000",
      "/oidc": "http://127.0.0.1:4000",
      "/plugins": "http://127.0.0.1:4000",
      "/debug": "http://127.0.0.1:4000",
      "/.well-known": "http://127.0.0.1:4000",
      "/me": "http://127.0.0.1:4000",
      "/health": "http://127.0.0.1:4000",
    },
  },
});
