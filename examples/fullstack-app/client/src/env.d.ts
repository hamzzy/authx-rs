/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AUTHX_ISSUER: string;
  readonly VITE_AUTHX_CLIENT_ID: string;
  readonly VITE_AUTHX_REDIRECT_URI: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
