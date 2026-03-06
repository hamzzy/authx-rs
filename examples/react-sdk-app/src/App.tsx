import { useEffect, useState } from "react";

import {
  AuthxTokenProvider,
  useAccessToken,
  useAuthenticatedFetch,
  useIsAuthenticated,
} from "@authx-rs/sdk-react";

import { completeLoginFromCallback, startLogin, tokenManager } from "./auth";

function AuthPanel() {
  const accessToken = useAccessToken();
  const isAuthenticated = useIsAuthenticated();
  const authenticatedFetch = useAuthenticatedFetch();
  const [status, setStatus] = useState("idle");

  return (
    <main style={{ fontFamily: "ui-sans-serif, system-ui", margin: "3rem auto", maxWidth: 720 }}>
      <h1>authx React SDK Example</h1>
      <p>
        This example uses <code>@authx-rs/sdk</code>, <code>@authx-rs/sdk-web</code>, and
        <code> @authx-rs/sdk-react</code>.
      </p>
      <p>Status: {isAuthenticated ? "authenticated" : "signed out"}</p>
      <p>Access token: {accessToken ? `${accessToken.slice(0, 16)}...` : "none"}</p>
      <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
        <button onClick={() => void startLogin()}>Start OIDC Login</button>
        <button
          onClick={() =>
            void tokenManager.clear().then(() => {
              setStatus("tokens cleared");
            })
          }
        >
          Clear Tokens
        </button>
        <button
          onClick={() =>
            void authenticatedFetch("https://httpbin.org/headers")
              .then((response) => response.json())
              .then(() => setStatus("authenticated fetch completed"))
              .catch((error: unknown) => setStatus(String(error)))
          }
        >
          Test Authenticated Fetch
        </button>
      </div>
      <p>{status}</p>
    </main>
  );
}

export default function App() {
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    void tokenManager
      .start()
      .then(() => completeLoginFromCallback())
      .catch((cause: unknown) => {
        if (active) {
          setError(String(cause));
        }
      })
      .finally(() => {
        if (active) {
          setReady(true);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  if (!ready) {
    return <main style={{ padding: "3rem" }}>Loading auth state...</main>;
  }

  if (error) {
    return <main style={{ padding: "3rem" }}>{error}</main>;
  }

  return (
    <AuthxTokenProvider client={tokenManager}>
      <AuthPanel />
    </AuthxTokenProvider>
  );
}
