import { useEffect, useState, type FormEvent } from "react";

import {
  AuthxTokenProvider,
  useAuthxSnapshot,
  useAuthxToken,
  useIsAuthenticated,
} from "@authx-rs/sdk-react";

import {
  api,
  completeLoginFromCallback,
  discoverExampleIssuer,
  getExampleConfig,
  getRememberedUserId,
  rememberUserId,
  setSessionCookieFromToken,
  startOidcLogin,
  tokenManager,
  type ApiResult,
  type ExampleConfig,
} from "./auth";

interface UserInfo {
  user_id: string;
  email: string;
  verified: boolean;
  active_org?: string | null;
}

interface AdminUserRecord {
  id: string;
  email: string;
  email_verified: boolean;
  username?: string | null;
  created_at: string;
  updated_at: string;
  metadata: unknown;
}

interface SessionInfo {
  id: string;
  ip_address: string;
  created_at: string;
}

interface ApiKeyRecord {
  id: string;
  user_id: string;
  org_id?: string | null;
  prefix: string;
  name: string;
  scopes: string[];
  expires_at?: string | null;
  last_used_at?: string | null;
}

interface OrgRecord {
  id: string;
  name: string;
  slug: string;
  metadata: unknown;
  created_at: string;
}

interface RoleRecord {
  id: string;
  org_id: string;
  name: string;
  permissions: string[];
}

interface MembershipRecord {
  id: string;
  user_id: string;
  org_id: string;
  role: RoleRecord;
  created_at: string;
}

interface TotpSetupData {
  otpauth_uri: string;
  secret: string;
  backup_codes: string[];
}

interface DeviceAuthorizationData {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

interface WebAuthnBeginData {
  challenge: string;
  user_id: string;
  timeout_secs: number;
  options: unknown;
}

interface WebAuthnFinishData {
  user_id: string;
  session_id?: string;
  token?: string;
  credential_stored?: boolean;
}

const styles = {
  page: {
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    maxWidth: 1100,
    margin: "0 auto",
    padding: "2rem 1rem 4rem",
  },
  header: {
    display: "grid",
    gap: "0.75rem",
    marginBottom: "1.25rem",
  },
  title: { fontSize: "1.8rem", margin: 0 },
  muted: { color: "#57606a", fontSize: "0.92rem", lineHeight: 1.55 },
  grid: { display: "grid", gap: "1rem", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))" },
  card: {
    border: "1px solid #d0d7de",
    borderRadius: 12,
    padding: "1rem 1.1rem",
    background: "#fff",
    boxShadow: "0 1px 0 rgba(27,31,36,0.04)",
  },
  input: {
    width: "100%",
    padding: "0.58rem 0.7rem",
    border: "1px solid #d0d7de",
    borderRadius: 8,
    font: "inherit",
    fontSize: "0.92rem",
    boxSizing: "border-box" as const,
    marginBottom: "0.65rem",
  },
  btn: {
    padding: "0.55rem 0.9rem",
    border: "none",
    borderRadius: 8,
    fontWeight: 600,
    cursor: "pointer",
    fontSize: "0.9rem",
    color: "#fff",
    background: "#0969da",
  },
  btnOutline: {
    padding: "0.55rem 0.9rem",
    border: "1px solid #d0d7de",
    borderRadius: 8,
    fontWeight: 600,
    cursor: "pointer",
    fontSize: "0.9rem",
    color: "#0969da",
    background: "transparent",
  },
  btnDanger: {
    padding: "0.55rem 0.9rem",
    border: "none",
    borderRadius: 8,
    fontWeight: 600,
    cursor: "pointer",
    fontSize: "0.9rem",
    color: "#fff",
    background: "#cf222e",
  },
  buttonRow: {
    display: "flex",
    gap: "0.5rem",
    flexWrap: "wrap" as const,
    marginTop: "0.55rem",
  },
  code: {
    background: "#f6f8fa",
    padding: "0.1rem 0.3rem",
    borderRadius: 4,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    fontSize: "0.85rem",
  },
  pre: {
    background: "#f6f8fa",
    borderRadius: 8,
    padding: "0.85rem",
    fontSize: "0.78rem",
    overflowX: "auto" as const,
    marginTop: "0.65rem",
    lineHeight: 1.45,
  },
  badge: (color: string, bg: string) => ({
    display: "inline-block",
    fontSize: "0.75rem",
    fontWeight: 600,
    padding: "0.18rem 0.52rem",
    borderRadius: 999,
    background: bg,
    color,
  }),
  msgOk: {
    marginTop: "0.65rem",
    padding: "0.58rem 0.75rem",
    borderRadius: 8,
    fontSize: "0.88rem",
    background: "#dafbe1",
    color: "#1a7f37",
  },
  msgErr: {
    marginTop: "0.65rem",
    padding: "0.58rem 0.75rem",
    borderRadius: 8,
    fontSize: "0.88rem",
    background: "#ffebe9",
    color: "#cf222e",
  },
  label: { display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: "0.25rem" },
  inlineList: { display: "flex", flexWrap: "wrap" as const, gap: "0.5rem", alignItems: "center" },
} as const;

function formatValue(value: unknown) {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value, null, 2);
}

function StatusMessage(props: { text: string; ok: boolean }) {
  return <div style={props.ok ? styles.msgOk : styles.msgErr}>{props.text}</div>;
}

function ResponseBlock(props: { title: string; value: unknown }) {
  if (props.value === null || props.value === undefined || props.value === "") {
    return null;
  }
  return (
    <div style={{ marginTop: "0.65rem" }}>
      <div style={{ fontSize: "0.8rem", fontWeight: 600, marginBottom: "0.25rem" }}>{props.title}</div>
      <pre style={styles.pre}>{formatValue(props.value)}</pre>
    </div>
  );
}

function RuntimeConfigCard({ config }: { config: ExampleConfig | null }) {
  return (
    <div style={styles.card}>
      <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>Runtime Config</h2>
      <p style={styles.muted}>
        The frontend now loads its live demo configuration from <span style={styles.code}>/debug/config</span>, so backend restarts are easier to test.
      </p>
      <ResponseBlock title="Current config" value={config} />
    </div>
  );
}

function AuthForms({
  onLogin,
  config,
}: {
  onLogin: () => void;
  config: ExampleConfig | null;
}) {
  const [tab, setTab] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  async function handleSignUp(e: FormEvent) {
    e.preventDefault();
    const res = await api.post<{ user_id: string; email: string }>("/auth/sign-up", { email, password });
    if (res.ok) {
      rememberUserId(res.data?.user_id);
      setMsg({ text: "Account created. Sign in, then use the extra debug flows below.", ok: true });
      setTab("signin");
    } else {
      setMsg({ text: res.data && "error" in res.data ? String((res.data as { error?: string }).error) : `Error (${res.status})`, ok: false });
    }
  }

  async function handleSignIn(e: FormEvent) {
    e.preventDefault();
    const res = await api.post<{ user_id: string }>("/auth/sign-in", { email, password });
    if (res.ok) {
      rememberUserId(res.data?.user_id);
      onLogin();
    } else {
      setMsg({ text: res.data && "error" in res.data ? String((res.data as { error?: string }).error) : `Invalid credentials (${res.status})`, ok: false });
    }
  }

  return (
    <div style={styles.grid}>
      <div style={styles.card}>
        <div style={styles.inlineList}>
          <button
            style={{ ...styles.btn, ...(tab === "signin" ? {} : { background: "#fff", color: "#0969da", border: "1px solid #d0d7de" }) }}
            onClick={() => {
              setTab("signin");
              setMsg(null);
            }}
          >
            Sign In
          </button>
          <button
            style={{ ...styles.btn, ...(tab === "signup" ? {} : { background: "#fff", color: "#0969da", border: "1px solid #d0d7de" }) }}
            onClick={() => {
              setTab("signup");
              setMsg(null);
            }}
          >
            Sign Up
          </button>
        </div>

        <h2 style={{ fontSize: "1rem", margin: "1rem 0 0.65rem" }}>
          {tab === "signin" ? "Email/Password Session" : "Create Account"}
        </h2>
        <form onSubmit={tab === "signin" ? handleSignIn : handleSignUp}>
          <label style={styles.label}>Email</label>
          <input
            style={styles.input}
            type="email"
            required
            placeholder="alice@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <label style={styles.label}>Password</label>
          <input
            style={styles.input}
            type="password"
            required
            minLength={8}
            placeholder="min 8 characters"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button style={styles.btn} type="submit">
            {tab === "signin" ? "Sign In" : "Create Account"}
          </button>
        </form>
        {msg && <StatusMessage text={msg.text} ok={msg.ok} />}
      </div>

      <PasskeyLoginCard onLogin={onLogin} />

      <div style={styles.card}>
        <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>OIDC Demo Contract</h2>
        <p style={styles.muted}>
          This app uses authx as both the backend and the OIDC provider. The
          <span style={styles.code}> /oidc/authorize </span>
          route reuses the existing authx session cookie, so sign in above first and then run the OIDC flow from the authenticated dashboard.
        </p>
        <ResponseBlock title="Resolved runtime config" value={config} />
      </div>
    </div>
  );
}

function PasskeyLoginCard({ onLogin }: { onLogin: () => void }) {
  const [userId, setUserId] = useState(getRememberedUserId());
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [beginPayload, setBeginPayload] = useState<unknown>(null);
  const [finishPayload, setFinishPayload] = useState<unknown>(null);
  const supported = typeof window !== "undefined" && "PublicKeyCredential" in window;

  async function loginWithPasskey() {
    setMsg(null);
    setFinishPayload(null);

    if (!supported) {
      setMsg({ text: "WebAuthn is not available in this browser.", ok: false });
      return;
    }
    if (!userId) {
      setMsg({ text: "Enter a user_id from a previous sign-in or sign-up first.", ok: false });
      return;
    }

    const begin = await api.post<WebAuthnBeginData>("/auth/webauthn/login/begin", { user_id: userId });
    setBeginPayload(begin.data ?? begin.text);
    if (!begin.ok || !begin.data) {
      setMsg({ text: extractError(begin), ok: false });
      return;
    }

    try {
      const credential = await runPasskeyAuthentication(begin.data.options);
      const finish = await api.post<WebAuthnFinishData>("/auth/webauthn/login/finish", {
        challenge: begin.data.challenge,
        credential,
        ip: "127.0.0.1",
      });
      setFinishPayload(finish.data ?? finish.text);
      if (!finish.ok || !finish.data?.token) {
        setMsg({ text: extractError(finish), ok: false });
        return;
      }
      rememberUserId(finish.data.user_id);
      await setSessionCookieFromToken(finish.data.token);
      setMsg({ text: "Passkey login succeeded and the cookie session is now active.", ok: true });
      onLogin();
    } catch (error) {
      setMsg({ text: String(error), ok: false });
    }
  }

  return (
    <div style={styles.card}>
      <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>Passkey Login</h2>
      <p style={styles.muted}>
        Use this after you have registered a passkey for a user. The demo remembers the last seen <span style={styles.code}>user_id</span> locally.
      </p>
      <label style={styles.label}>User ID</label>
      <input
        style={styles.input}
        placeholder="UUID from sign-up, /me, or Runtime Config panels"
        value={userId}
        onChange={(e) => setUserId(e.target.value)}
      />
      <button style={styles.btnOutline} onClick={() => void loginWithPasskey()}>
        Login With Passkey
      </button>
      {msg && <StatusMessage text={msg.text} ok={msg.ok} />}
      <ResponseBlock title="Passkey login begin" value={beginPayload} />
      <ResponseBlock title="Passkey login finish" value={finishPayload} />
    </div>
  );
}

function TotpSection() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [setup, setSetup] = useState<TotpSetupData | null>(null);
  const [code, setCode] = useState("");
  const [verifyCode, setVerifyCode] = useState("");
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  async function loadStatus() {
    const res = await api.get<{ enabled: boolean }>("/auth/totp/status");
    if (res.ok && res.data) {
      setEnabled(res.data.enabled);
    }
  }

  useEffect(() => {
    void loadStatus();
  }, []);

  async function beginSetup() {
    const res = await api.post<TotpSetupData>("/auth/totp/setup", {});
    if (res.ok && res.data) {
      setSetup(res.data);
      setMsg(null);
    } else {
      setMsg({ text: extractError(res), ok: false });
    }
  }

  async function confirmSetup(e: FormEvent) {
    e.preventDefault();
    const res = await api.post<{ message: string }>("/auth/totp/confirm", { code });
    if (res.ok) {
      setMsg({ text: "TOTP enabled.", ok: true });
      setSetup(null);
      setCode("");
      void loadStatus();
    } else {
      setMsg({ text: extractError(res), ok: false });
    }
  }

  async function verifyTotp(e: FormEvent) {
    e.preventDefault();
    const res = await api.post<{ message: string }>("/auth/totp/verify", { code: verifyCode });
    setMsg({ text: res.ok ? "Code verified." : extractError(res), ok: res.ok });
    setVerifyCode("");
  }

  if (enabled === null) {
    return null;
  }

  return (
    <div style={styles.card}>
      <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>TOTP / MFA</h2>
      <div style={styles.inlineList}>
        <span style={enabled ? styles.badge("#1a7f37", "#dafbe1") : styles.badge("#cf222e", "#ffebe9")}>
          {enabled ? "Enabled" : "Not enabled"}
        </span>
        {!enabled && (
          <button style={styles.btnOutline} onClick={() => void beginSetup()}>
            Begin TOTP Setup
          </button>
        )}
      </div>

      {setup && (
        <div style={{ marginTop: "0.75rem" }}>
          <p style={styles.muted}>Scan the URI below, then confirm with a six-digit code.</p>
          <ResponseBlock title="otpauth_uri" value={setup.otpauth_uri} />
          <ResponseBlock title="shared secret" value={setup.secret} />
          <ResponseBlock title="backup codes" value={setup.backup_codes} />
          <form onSubmit={confirmSetup}>
            <label style={styles.label}>Confirm TOTP code</label>
            <input
              style={styles.input}
              maxLength={6}
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
            <button style={styles.btn} type="submit">
              Confirm TOTP
            </button>
          </form>
        </div>
      )}

      {enabled && (
        <form onSubmit={verifyTotp} style={{ marginTop: "0.75rem" }}>
          <label style={styles.label}>Verify current TOTP</label>
          <input
            style={styles.input}
            maxLength={6}
            placeholder="123456"
            value={verifyCode}
            onChange={(e) => setVerifyCode(e.target.value)}
          />
          <button style={styles.btn} type="submit">
            Verify TOTP
          </button>
        </form>
      )}

      {msg && <StatusMessage text={msg.text} ok={msg.ok} />}
    </div>
  );
}

function SessionsSection() {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [rawSession, setRawSession] = useState<unknown>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  async function load() {
    const [list, current] = await Promise.all([
      api.get<SessionInfo[]>("/auth/sessions"),
      api.get("/auth/session"),
    ]);
    if (list.ok && Array.isArray(list.data)) {
      setSessions(list.data);
    }
    setRawSession(current.data ?? current.text);
  }

  useEffect(() => {
    void load();
  }, []);

  async function revoke(id: string) {
    const res = await api.delete(`/auth/sessions/${id}`);
    setMsg({ text: res.ok ? `Session ${id} revoked.` : extractError(res), ok: res.ok });
    void load();
  }

  return (
    <div style={styles.card}>
      <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>Sessions</h2>
      <div style={styles.buttonRow}>
        <button style={styles.btnOutline} onClick={() => void load()}>
          Refresh Sessions
        </button>
      </div>
      {sessions.length === 0 ? (
        <p style={styles.muted}>No active sessions found.</p>
      ) : (
        sessions.map((session) => (
          <div
            key={session.id}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "0.75rem",
              padding: "0.55rem 0",
              borderBottom: "1px solid #d8dee4",
              fontSize: "0.86rem",
            }}
          >
            <div>
              <span style={styles.code}>{session.id.slice(0, 8)}...</span>
              <span style={{ marginLeft: "0.4rem", color: "#57606a" }}>{session.ip_address || "unknown ip"}</span>
              <span style={{ marginLeft: "0.4rem", color: "#57606a" }}>{new Date(session.created_at).toLocaleString()}</span>
            </div>
            <button style={styles.btnOutline} onClick={() => void revoke(session.id)}>
              Revoke
            </button>
          </div>
        ))
      )}
      {msg && <StatusMessage text={msg.text} ok={msg.ok} />}
      <ResponseBlock title="/auth/session response" value={rawSession} />
    </div>
  );
}

function PasskeySection({
  user,
  onSessionRefresh,
}: {
  user: UserInfo;
  onSessionRefresh: () => void;
}) {
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [registerBegin, setRegisterBegin] = useState<unknown>(null);
  const [registerFinish, setRegisterFinish] = useState<unknown>(null);
  const [loginBegin, setLoginBegin] = useState<unknown>(null);
  const [loginFinish, setLoginFinish] = useState<unknown>(null);
  const supported = typeof window !== "undefined" && "PublicKeyCredential" in window;

  async function registerPasskey() {
    setMsg(null);
    const begin = await api.post<WebAuthnBeginData>("/auth/webauthn/register/begin", { user_id: user.user_id });
    setRegisterBegin(begin.data ?? begin.text);
    if (!begin.ok || !begin.data) {
      setMsg({ text: extractError(begin), ok: false });
      return;
    }

    try {
      const credential = await runPasskeyRegistration(begin.data.options);
      const finish = await api.post<WebAuthnFinishData>("/auth/webauthn/register/finish", {
        challenge: begin.data.challenge,
        credential,
      });
      setRegisterFinish(finish.data ?? finish.text);
      setMsg({
        text: finish.ok ? "Passkey registered for this user." : extractError(finish),
        ok: finish.ok,
      });
    } catch (error) {
      setMsg({ text: String(error), ok: false });
    }
  }

  async function testPasskeyLogin() {
    setMsg(null);
    const begin = await api.post<WebAuthnBeginData>("/auth/webauthn/login/begin", { user_id: user.user_id });
    setLoginBegin(begin.data ?? begin.text);
    if (!begin.ok || !begin.data) {
      setMsg({ text: extractError(begin), ok: false });
      return;
    }

    try {
      const credential = await runPasskeyAuthentication(begin.data.options);
      const finish = await api.post<WebAuthnFinishData>("/auth/webauthn/login/finish", {
        challenge: begin.data.challenge,
        credential,
        ip: "127.0.0.1",
      });
      setLoginFinish(finish.data ?? finish.text);
      if (!finish.ok || !finish.data?.token) {
        setMsg({ text: extractError(finish), ok: false });
        return;
      }
      await setSessionCookieFromToken(finish.data.token);
      rememberUserId(finish.data.user_id);
      setMsg({ text: "Passkey login finished and refreshed the session cookie.", ok: true });
      onSessionRefresh();
    } catch (error) {
      setMsg({ text: String(error), ok: false });
    }
  }

  return (
    <div style={styles.card}>
      <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>Passkeys / WebAuthn</h2>
      <p style={styles.muted}>
        Register a passkey for the current user, then test the login ceremony immediately or use the logged-out panel.
      </p>
      <div style={styles.inlineList}>
        <span style={supported ? styles.badge("#1a7f37", "#dafbe1") : styles.badge("#cf222e", "#ffebe9")}>
          {supported ? "Browser supports WebAuthn" : "WebAuthn unavailable"}
        </span>
        <span style={styles.code}>{user.user_id}</span>
      </div>
      <div style={styles.buttonRow}>
        <button style={styles.btnOutline} onClick={() => void registerPasskey()} disabled={!supported}>
          Register Passkey
        </button>
        <button style={styles.btnOutline} onClick={() => void testPasskeyLogin()} disabled={!supported}>
          Test Passkey Login
        </button>
      </div>
      {msg && <StatusMessage text={msg.text} ok={msg.ok} />}
      <ResponseBlock title="register begin" value={registerBegin} />
      <ResponseBlock title="register finish" value={registerFinish} />
      <ResponseBlock title="login begin" value={loginBegin} />
      <ResponseBlock title="login finish" value={loginFinish} />
    </div>
  );
}

function OidcToolsSection({ config }: { config: ExampleConfig | null }) {
  const auth = useAuthxToken();
  const snapshot = useAuthxSnapshot();
  const [discovery, setDiscovery] = useState<unknown>(null);
  const [userinfo, setUserinfo] = useState<unknown>(null);
  const [introspection, setIntrospection] = useState<unknown>(null);
  const [revokeResult, setRevokeResult] = useState<unknown>(null);
  const [refreshResult, setRefreshResult] = useState<unknown>(null);
  const [deviceScope, setDeviceScope] = useState("openid profile email offline_access");
  const [deviceGrant, setDeviceGrant] = useState<DeviceAuthorizationData | null>(null);
  const [devicePoll, setDevicePoll] = useState<unknown>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  useEffect(() => {
    void discoverExampleIssuer().then(setDiscovery).catch((error) => setDiscovery({ error: String(error) }));
  }, []);

  const accessToken = snapshot.tokens?.accessToken ?? "";
  const refreshToken = snapshot.tokens?.refreshToken ?? "";

  async function reloadDiscovery() {
    try {
      setDiscovery(await discoverExampleIssuer());
    } catch (error) {
      setDiscovery({ error: String(error) });
    }
  }

  async function callUserinfo() {
    if (!accessToken) {
      setMsg({ text: "No access token available yet.", ok: false });
      return;
    }
    const res = await fetch("/oidc/userinfo", {
      credentials: "same-origin",
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    setUserinfo(await res.text().then((text) => {
      try {
        return JSON.parse(text);
      } catch {
        return text;
      }
    }));
  }

  async function introspectToken(token: string, hint: "access_token" | "refresh_token") {
    if (!config || !token) {
      setMsg({ text: "Missing config or token for introspection.", ok: false });
      return;
    }
    const res = await api.postForm("/oidc/introspect", {
      token,
      token_type_hint: hint,
      client_id: config.oidcClientId,
    });
    setIntrospection(res.data ?? res.text);
  }

  async function revokeToken(token: string, hint: "access_token" | "refresh_token") {
    if (!config || !token) {
      setMsg({ text: "Missing config or token for revocation.", ok: false });
      return;
    }
    const res = await api.postForm("/oidc/revoke", {
      token,
      token_type_hint: hint,
      client_id: config.oidcClientId,
    });
    setRevokeResult(res.data ?? res.text ?? { status: res.status });
    if (res.ok && hint === "refresh_token") {
      await auth.clear();
    }
  }

  async function refreshTokens() {
    try {
      const next = await auth.refresh();
      setRefreshResult(next);
      setMsg({ text: "Refresh token exchange succeeded.", ok: true });
    } catch (error) {
      setRefreshResult({ error: String(error) });
      setMsg({ text: String(error), ok: false });
    }
  }

  async function requestDeviceCode() {
    if (!config) {
      setMsg({ text: "Runtime config is still loading.", ok: false });
      return;
    }
    const res = await api.postForm<DeviceAuthorizationData>("/oidc/device_authorization", {
      client_id: config.oidcClientId,
      scope: deviceScope,
    });
    if (res.ok && res.data) {
      setDeviceGrant(res.data);
      setDevicePoll(null);
      setMsg({ text: "Device code issued. Open the verification page and then poll.", ok: true });
    } else {
      setMsg({ text: extractError(res), ok: false });
    }
  }

  async function pollDeviceCode() {
    if (!config || !deviceGrant) {
      setMsg({ text: "Request a device code first.", ok: false });
      return;
    }
    const res = await api.postForm("/oidc/token", {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      client_id: config.oidcClientId,
      device_code: deviceGrant.device_code,
    });
    setDevicePoll(res.data ?? res.text);
    if (res.ok && res.data && typeof res.data === "object" && "access_token" in res.data) {
      await auth.setTokenResponse(res.data as {
        access_token: string;
        token_type: string;
        expires_in: number;
        refresh_token?: string;
        id_token?: string;
        scope?: string;
      });
      setMsg({ text: "Device flow completed and tokens were loaded into the SDK store.", ok: true });
    } else if (!res.ok) {
      setMsg({ text: extractError(res), ok: false });
    }
  }

  return (
    <div style={styles.card}>
      <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>OIDC Debug Tools</h2>
      <div style={styles.inlineList}>
        <span style={snapshot.isAuthenticated ? styles.badge("#1a7f37", "#dafbe1") : styles.badge("#9a6700", "#fff8c5")}>
          {snapshot.isAuthenticated ? "OIDC tokens present" : "OIDC tokens missing"}
        </span>
        {config && <span style={styles.code}>{config.oidcClientId}</span>}
      </div>
      <div style={styles.buttonRow}>
        {!snapshot.isAuthenticated && (
          <button style={styles.btnOutline} onClick={() => void startOidcLogin()}>
            Start Authorization Code Flow
          </button>
        )}
        <button style={styles.btnOutline} onClick={() => void reloadDiscovery()}>
          Reload Discovery
        </button>
        <button style={styles.btnOutline} onClick={() => void callUserinfo()} disabled={!accessToken}>
          Call UserInfo
        </button>
        <button style={styles.btnOutline} onClick={() => void refreshTokens()} disabled={!refreshToken}>
          Refresh Tokens
        </button>
      </div>

      <div style={{ marginTop: "0.85rem" }}>
        <div style={{ fontSize: "0.85rem", fontWeight: 600 }}>Direct Token Operations</div>
        <div style={styles.buttonRow}>
          <button style={styles.btnOutline} onClick={() => void introspectToken(accessToken, "access_token")} disabled={!accessToken}>
            Introspect Access Token
          </button>
          <button style={styles.btnOutline} onClick={() => void introspectToken(refreshToken, "refresh_token")} disabled={!refreshToken}>
            Introspect Refresh Token
          </button>
          <button style={styles.btnDanger} onClick={() => void revokeToken(accessToken, "access_token")} disabled={!accessToken}>
            Revoke Access Token
          </button>
          <button style={styles.btnDanger} onClick={() => void revokeToken(refreshToken, "refresh_token")} disabled={!refreshToken}>
            Revoke Refresh Token
          </button>
        </div>
      </div>

      <div style={{ marginTop: "1rem" }}>
        <div style={{ fontSize: "0.85rem", fontWeight: 600 }}>Device Authorization Grant</div>
        <label style={{ ...styles.label, marginTop: "0.5rem" }}>Scope</label>
        <input
          style={styles.input}
          value={deviceScope}
          onChange={(e) => setDeviceScope(e.target.value)}
        />
        <div style={styles.buttonRow}>
          <button style={styles.btnOutline} onClick={() => void requestDeviceCode()}>
            Request Device Code
          </button>
          <button style={styles.btnOutline} onClick={() => void pollDeviceCode()} disabled={!deviceGrant}>
            Poll Device Token
          </button>
          {deviceGrant?.verification_uri_complete && (
            <a href={deviceGrant.verification_uri_complete} target="_blank" rel="noreferrer">
              <button style={styles.btnOutline}>Open Verification Page</button>
            </a>
          )}
        </div>
      </div>

      {msg && <StatusMessage text={msg.text} ok={msg.ok} />}
      <ResponseBlock title="token snapshot" value={snapshot} />
      <ResponseBlock title="discovery document" value={discovery} />
      <ResponseBlock title="userinfo response" value={userinfo} />
      <ResponseBlock title="introspection response" value={introspection} />
      <ResponseBlock title="revoke response" value={revokeResult} />
      <ResponseBlock title="refresh result" value={refreshResult} />
      <ResponseBlock title="device authorization response" value={deviceGrant} />
      <ResponseBlock title="device poll response" value={devicePoll} />
    </div>
  );
}

function EndpointInspector() {
  const [health, setHealth] = useState<unknown>(null);
  const [jwks, setJwks] = useState<unknown>(null);
  const [me, setMe] = useState<unknown>(null);

  return (
    <div style={styles.card}>
      <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>Endpoint Smoke Tests</h2>
      <p style={styles.muted}>
        Quick read-only probes for the most useful demo endpoints while debugging.
      </p>
      <div style={styles.buttonRow}>
        <button style={styles.btnOutline} onClick={() => void api.get("/health").then((res) => setHealth(res.data ?? res.text))}>
          GET /health
        </button>
        <button style={styles.btnOutline} onClick={() => void api.get("/me").then((res) => setMe(res.data ?? res.text))}>
          GET /me
        </button>
        <button style={styles.btnOutline} onClick={() => void api.get("/oidc/jwks").then((res) => setJwks(res.data ?? res.text))}>
          GET /oidc/jwks
        </button>
      </div>
      <ResponseBlock title="/health" value={health} />
      <ResponseBlock title="/me" value={me} />
      <ResponseBlock title="/oidc/jwks" value={jwks} />
    </div>
  );
}

function ApiKeySection({ user }: { user: UserInfo }) {
  const [keys, setKeys] = useState<ApiKeyRecord[]>([]);
  const [name, setName] = useState("debug-key");
  const [scopes, setScopes] = useState("openid profile");
  const [days, setDays] = useState("30");
  const [testKey, setTestKey] = useState("");
  const [createdKey, setCreatedKey] = useState<unknown>(null);
  const [testResult, setTestResult] = useState<unknown>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  async function load() {
    const res = await api.get<ApiKeyRecord[]>("/plugins/api-keys");
    if (res.ok && Array.isArray(res.data)) {
      setKeys(res.data);
    } else {
      setMsg({ text: extractError(res), ok: false });
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function create() {
    const expiresInDays = Number(days);
    const res = await api.post("/plugins/api-keys", {
      name,
      scopes: scopes.split(/\s+/).filter(Boolean),
      expires_in_days: expiresInDays,
      org_id: user.active_org ?? null,
    });
    if (res.ok) {
      setCreatedKey(res.data ?? res.text);
      const rawKey = res.data && typeof res.data === "object" && "raw_key" in res.data
        ? String((res.data as { raw_key?: unknown }).raw_key ?? "")
        : "";
      if (rawKey) {
        setTestKey(rawKey);
      }
      setMsg({ text: "API key created. The raw key is shown once only.", ok: true });
      void load();
    } else {
      setMsg({ text: extractError(res), ok: false });
    }
  }

  async function revoke(id: string) {
    const res = await api.delete(`/plugins/api-keys/${id}`);
    setMsg({ text: res.ok ? `API key ${id} revoked.` : extractError(res), ok: res.ok });
    void load();
  }

  async function test() {
    const res = await api.post("/plugins/api-keys/test", { raw_key: testKey });
    setTestResult(res.data ?? res.text);
    setMsg({ text: res.ok ? "API key authenticated successfully." : extractError(res), ok: res.ok });
  }

  return (
    <div style={styles.card}>
      <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>Plugin: API Keys</h2>
      <p style={styles.muted}>
        Exercise the API key plugin by creating keys for the current user, revoking them, and testing raw-key authentication.
      </p>
      <label style={styles.label}>Key name</label>
      <input style={styles.input} value={name} onChange={(e) => setName(e.target.value)} />
      <label style={styles.label}>Scopes</label>
      <input style={styles.input} value={scopes} onChange={(e) => setScopes(e.target.value)} />
      <label style={styles.label}>Expires in days</label>
      <input style={styles.input} value={days} onChange={(e) => setDays(e.target.value)} />
      <div style={styles.buttonRow}>
        <button style={styles.btnOutline} onClick={() => void create()}>
          Create API Key
        </button>
        <button style={styles.btnOutline} onClick={() => void load()}>
          Refresh Keys
        </button>
      </div>

      <label style={{ ...styles.label, marginTop: "0.9rem" }}>Test raw API key</label>
      <input style={styles.input} value={testKey} onChange={(e) => setTestKey(e.target.value)} />
      <button style={styles.btnOutline} onClick={() => void test()} disabled={!testKey}>
        Authenticate Raw Key
      </button>

      {keys.length > 0 && (
        <div style={{ marginTop: "0.9rem" }}>
          {keys.map((key) => (
            <div
              key={key.id}
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "0.75rem",
                padding: "0.5rem 0",
                borderBottom: "1px solid #d8dee4",
                fontSize: "0.85rem",
              }}
            >
              <div>
                <span style={styles.code}>{key.prefix}</span>
                <span style={{ marginLeft: "0.45rem" }}>{key.name}</span>
                <span style={{ marginLeft: "0.45rem", color: "#57606a" }}>{key.scopes.join(", ") || "no scopes"}</span>
              </div>
              <button style={styles.btnOutline} onClick={() => void revoke(key.id)}>
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}

      {msg && <StatusMessage text={msg.text} ok={msg.ok} />}
      <ResponseBlock title="create api key response" value={createdKey} />
      <ResponseBlock title="api key test response" value={testResult} />
    </div>
  );
}

function AdminSection({ onSessionRefresh }: { onSessionRefresh: () => void }) {
  const [users, setUsers] = useState<AdminUserRecord[]>([]);
  const [email, setEmail] = useState("debug-user@example.com");
  const [targetUserId, setTargetUserId] = useState("");
  const [banReason, setBanReason] = useState("debug bench ban");
  const [sessions, setSessions] = useState<unknown>(null);
  const [result, setResult] = useState<unknown>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  async function loadUsers() {
    const res = await api.get<AdminUserRecord[]>("/plugins/admin/users");
    if (res.ok && Array.isArray(res.data)) {
      setUsers(res.data);
      if (!targetUserId && res.data[0]) {
        setTargetUserId(res.data[0].id);
      }
    } else {
      setMsg({ text: extractError(res), ok: false });
    }
  }

  useEffect(() => {
    void loadUsers();
  }, []);

  async function createUser() {
    const res = await api.post("/plugins/admin/users", { email });
    setResult(res.data ?? res.text);
    setMsg({ text: res.ok ? "Admin-created user added." : extractError(res), ok: res.ok });
    void loadUsers();
  }

  async function ban() {
    const res = await api.post(`/plugins/admin/users/${targetUserId}/ban`, { reason: banReason });
    setResult(res.data ?? res.text);
    setMsg({ text: res.ok ? "User banned." : extractError(res), ok: res.ok });
    void loadUsers();
  }

  async function unban() {
    const res = await api.delete(`/plugins/admin/users/${targetUserId}/ban`);
    setResult(res.data ?? res.text);
    setMsg({ text: res.ok ? "User unbanned." : extractError(res), ok: res.ok });
    void loadUsers();
  }

  async function listTargetSessions() {
    const res = await api.get(`/plugins/admin/users/${targetUserId}/sessions`);
    setSessions(res.data ?? res.text);
    setMsg({ text: res.ok ? "Loaded target sessions." : extractError(res), ok: res.ok });
  }

  async function revokeTargetSessions() {
    const res = await api.delete(`/plugins/admin/users/${targetUserId}/sessions`);
    setResult(res.data ?? res.text);
    setMsg({ text: res.ok ? "All target sessions revoked." : extractError(res), ok: res.ok });
    setSessions(null);
  }

  async function impersonate() {
    const res = await api.post(`/plugins/admin/users/${targetUserId}/impersonate`, {});
    setResult(res.data ?? res.text);
    if (res.ok) {
      setMsg({ text: "Impersonation cookie applied. Session view will refresh as the target user.", ok: true });
      onSessionRefresh();
    } else {
      setMsg({ text: extractError(res), ok: false });
    }
  }

  return (
    <div style={styles.card}>
      <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>Plugin: Admin</h2>
      <p style={styles.muted}>
        Demo-only admin endpoints for user provisioning, banning, session revocation, and impersonation.
      </p>
      <label style={styles.label}>Create user email</label>
      <input style={styles.input} value={email} onChange={(e) => setEmail(e.target.value)} />
      <div style={styles.buttonRow}>
        <button style={styles.btnOutline} onClick={() => void createUser()}>
          Create Admin User
        </button>
        <button style={styles.btnOutline} onClick={() => void loadUsers()}>
          Refresh Users
        </button>
      </div>

      <label style={{ ...styles.label, marginTop: "0.9rem" }}>Target user id</label>
      <input style={styles.input} value={targetUserId} onChange={(e) => setTargetUserId(e.target.value)} />
      <label style={styles.label}>Ban reason</label>
      <input style={styles.input} value={banReason} onChange={(e) => setBanReason(e.target.value)} />
      <div style={styles.buttonRow}>
        <button style={styles.btnOutline} onClick={() => void ban()} disabled={!targetUserId}>
          Ban User
        </button>
        <button style={styles.btnOutline} onClick={() => void unban()} disabled={!targetUserId}>
          Unban User
        </button>
        <button style={styles.btnOutline} onClick={() => void listTargetSessions()} disabled={!targetUserId}>
          List Target Sessions
        </button>
        <button style={styles.btnDanger} onClick={() => void revokeTargetSessions()} disabled={!targetUserId}>
          Revoke Target Sessions
        </button>
        <button style={styles.btnOutline} onClick={() => void impersonate()} disabled={!targetUserId}>
          Impersonate User
        </button>
      </div>

      {users.length > 0 && <ResponseBlock title="admin user list" value={users} />}
      {msg && <StatusMessage text={msg.text} ok={msg.ok} />}
      <ResponseBlock title="admin action response" value={result} />
      <ResponseBlock title="target sessions" value={sessions} />
    </div>
  );
}

function OrganizationSection({
  user,
  onSessionRefresh,
}: {
  user: UserInfo;
  onSessionRefresh: () => void;
}) {
  const [orgId, setOrgId] = useState(user.active_org ?? "");
  const [orgName, setOrgName] = useState("Debug Organization");
  const [orgSlug, setOrgSlug] = useState("debug-org");
  const [roleName, setRoleName] = useState("member");
  const [permissions, setPermissions] = useState("read:demo write:demo");
  const [inviteEmail, setInviteEmail] = useState("invitee@example.com");
  const [inviteRoleId, setInviteRoleId] = useState("");
  const [inviteToken, setInviteToken] = useState("");
  const [orgData, setOrgData] = useState<unknown>(null);
  const [roles, setRoles] = useState<RoleRecord[]>([]);
  const [members, setMembers] = useState<unknown>(null);
  const [inviteResult, setInviteResult] = useState<unknown>(null);
  const [switchResult, setSwitchResult] = useState<unknown>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  async function create() {
    const res = await api.post("/plugins/orgs", { name: orgName, slug: orgSlug });
    setOrgData(res.data ?? res.text);
    if (res.ok && res.data && typeof res.data === "object" && "org" in res.data) {
      const nextOrgId = String((res.data as { org?: { id?: unknown } }).org?.id ?? "");
      setOrgId(nextOrgId);
    }
    setMsg({ text: res.ok ? "Organization created." : extractError(res), ok: res.ok });
  }

  async function loadOrg() {
    if (!orgId) {
      setMsg({ text: "Enter an organization id first.", ok: false });
      return;
    }
    const [orgRes, roleRes, memberRes] = await Promise.all([
      api.get<OrgRecord>(`/plugins/orgs/${orgId}`),
      api.get<RoleRecord[]>(`/plugins/orgs/${orgId}/roles`),
      api.get<MembershipRecord[]>(`/plugins/orgs/${orgId}/members`),
    ]);
    setOrgData(orgRes.data ?? orgRes.text);
    setMembers(memberRes.data ?? memberRes.text);
    if (roleRes.ok && Array.isArray(roleRes.data)) {
      setRoles(roleRes.data);
      if (!inviteRoleId && roleRes.data[0]) {
        setInviteRoleId(roleRes.data[0].id);
      }
    }
    if (!orgRes.ok) {
      setMsg({ text: extractError(orgRes), ok: false });
    }
  }

  async function createRole() {
    if (!orgId) {
      setMsg({ text: "Create or load an org first.", ok: false });
      return;
    }
    const res = await api.post<RoleRecord>(`/plugins/orgs/${orgId}/roles`, {
      name: roleName,
      permissions: permissions.split(/\s+/).filter(Boolean),
    });
    setMsg({ text: res.ok ? "Role created." : extractError(res), ok: res.ok });
    if (res.ok) {
      void loadOrg();
    }
  }

  async function createInvite() {
    if (!orgId || !inviteRoleId) {
      setMsg({ text: "Need org id and role id before creating an invite.", ok: false });
      return;
    }
    const res = await api.post(`/plugins/orgs/${orgId}/invites`, {
      email: inviteEmail,
      role_id: inviteRoleId,
    });
    setInviteResult(res.data ?? res.text);
    if (res.ok && res.data && typeof res.data === "object" && "raw_token" in res.data) {
      setInviteToken(String((res.data as { raw_token?: unknown }).raw_token ?? ""));
    }
    setMsg({ text: res.ok ? "Invite created. Raw token is shown below." : extractError(res), ok: res.ok });
  }

  async function acceptInvite() {
    const res = await api.post("/plugins/orgs/invites/accept", { token: inviteToken });
    setInviteResult(res.data ?? res.text);
    setMsg({ text: res.ok ? "Invite accepted." : extractError(res), ok: res.ok });
    if (res.ok) {
      void loadOrg();
    }
  }

  async function switchOrg() {
    const res = await api.post("/plugins/orgs/switch", { org_id: orgId || null });
    setSwitchResult(res.data ?? res.text);
    setMsg({ text: res.ok ? "Active org switched on the session." : extractError(res), ok: res.ok });
    if (res.ok) {
      onSessionRefresh();
    }
  }

  return (
    <div style={styles.card}>
      <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>Plugin: Organizations</h2>
      <p style={styles.muted}>
        Create orgs, roles, and invites, then switch the active organization on the current session.
      </p>
      <label style={styles.label}>Organization name</label>
      <input style={styles.input} value={orgName} onChange={(e) => setOrgName(e.target.value)} />
      <label style={styles.label}>Organization slug</label>
      <input style={styles.input} value={orgSlug} onChange={(e) => setOrgSlug(e.target.value)} />
      <div style={styles.buttonRow}>
        <button style={styles.btnOutline} onClick={() => void create()}>
          Create Org
        </button>
      </div>

      <label style={{ ...styles.label, marginTop: "0.9rem" }}>Organization id</label>
      <input style={styles.input} value={orgId} onChange={(e) => setOrgId(e.target.value)} />
      <div style={styles.buttonRow}>
        <button style={styles.btnOutline} onClick={() => void loadOrg()} disabled={!orgId}>
          Load Org Data
        </button>
        <button style={styles.btnOutline} onClick={() => void switchOrg()}>
          Switch Active Org
        </button>
      </div>

      <label style={{ ...styles.label, marginTop: "0.9rem" }}>Role name</label>
      <input style={styles.input} value={roleName} onChange={(e) => setRoleName(e.target.value)} />
      <label style={styles.label}>Permissions</label>
      <input style={styles.input} value={permissions} onChange={(e) => setPermissions(e.target.value)} />
      <button style={styles.btnOutline} onClick={() => void createRole()} disabled={!orgId}>
        Create Role
      </button>

      <label style={{ ...styles.label, marginTop: "0.9rem" }}>Invite email</label>
      <input style={styles.input} value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} />
      <label style={styles.label}>Invite role id</label>
      <input style={styles.input} value={inviteRoleId} onChange={(e) => setInviteRoleId(e.target.value)} />
      <div style={styles.buttonRow}>
        <button style={styles.btnOutline} onClick={() => void createInvite()} disabled={!orgId || !inviteRoleId}>
          Create Invite
        </button>
      </div>

      <label style={{ ...styles.label, marginTop: "0.9rem" }}>Accept invite token</label>
      <input style={styles.input} value={inviteToken} onChange={(e) => setInviteToken(e.target.value)} />
      <button style={styles.btnOutline} onClick={() => void acceptInvite()} disabled={!inviteToken}>
        Accept Invite
      </button>

      {msg && <StatusMessage text={msg.text} ok={msg.ok} />}
      <ResponseBlock title="organization response" value={orgData} />
      <ResponseBlock title="org roles" value={roles} />
      <ResponseBlock title="org members" value={members} />
      <ResponseBlock title="invite response" value={inviteResult} />
      <ResponseBlock title="switch org response" value={switchResult} />
    </div>
  );
}

function Dashboard({
  user,
  onLogout,
  onSessionRefresh,
  config,
}: {
  user: UserInfo;
  onLogout: () => void;
  onSessionRefresh: () => void;
  config: ExampleConfig | null;
}) {
  const snapshot = useAuthxSnapshot();

  async function signOut() {
    await api.post("/auth/sign-out", {});
    await tokenManager.clear();
    onLogout();
  }

  async function signOutAll() {
    await api.post("/auth/sign-out/all", {});
    await tokenManager.clear();
    onLogout();
  }

  return (
    <div style={styles.grid}>
      <div style={styles.card}>
        <h2 style={{ fontSize: "1rem", marginBottom: "0.45rem" }}>Account</h2>
        <div style={styles.inlineList}>
          <span style={styles.badge(user.verified ? "#1a7f37" : "#9a6700", user.verified ? "#dafbe1" : "#fff8c5")}>
            {user.verified ? "Email verified" : "Email unverified"}
          </span>
          <span style={snapshot.isAuthenticated ? styles.badge("#1a7f37", "#dafbe1") : styles.badge("#9a6700", "#fff8c5")}>
            {snapshot.isAuthenticated ? "OIDC token store active" : "OIDC token store empty"}
          </span>
        </div>
        <p style={{ marginTop: "0.75rem", marginBottom: "0.2rem" }}>
          <strong>{user.email}</strong>
        </p>
        <p style={styles.muted}>
          user_id: <span style={styles.code}>{user.user_id}</span>
        </p>
        <div style={styles.buttonRow}>
          <button style={styles.btnOutline} onClick={() => void signOut()}>
            Sign Out
          </button>
          <button style={styles.btnDanger} onClick={() => void signOutAll()}>
            Sign Out All
          </button>
          <button style={styles.btnOutline} onClick={() => void onSessionRefresh()}>
            Refresh /me
          </button>
        </div>
      </div>

      <OidcToolsSection config={config} />
      <ApiKeySection user={user} />
      <AdminSection onSessionRefresh={onSessionRefresh} />
      <OrganizationSection user={user} onSessionRefresh={onSessionRefresh} />
      <PasskeySection user={user} onSessionRefresh={onSessionRefresh} />
      <TotpSection />
      <SessionsSection />
      <EndpointInspector />
    </div>
  );
}

function AppShell() {
  const isOidcAuthenticated = useIsAuthenticated();
  const snapshot = useAuthxSnapshot();
  const [config, setConfig] = useState<ExampleConfig | null>(null);
  const [sessionAuth, setSessionAuth] = useState<boolean | null>(null);
  const [user, setUser] = useState<UserInfo | null>(null);

  const checkSession = () => {
    void api.get<UserInfo>("/me").then((res) => {
      setSessionAuth(res.ok);
      if (res.ok && res.data) {
        setUser(res.data);
        rememberUserId(res.data.user_id);
      } else {
        setUser(null);
      }
    });
  };

  useEffect(() => {
    void getExampleConfig().then(setConfig).catch((error) => setConfig({
      backendUrl: "error",
      frontendUrl: window.location.origin,
      oidcClientId: String(error),
      oidcIssuer: "error",
      oidcRedirectUri: window.location.origin,
      webauthnRpId: "error",
      webauthnRpOrigin: window.location.origin,
    }));
  }, []);

  useEffect(() => {
    checkSession();
  }, [isOidcAuthenticated]);

  return (
    <div style={styles.page}>
      <div style={styles.header}>
        <h1 style={styles.title}>authx-rs fullstack debug bench</h1>
        <p style={styles.muted}>
          One app for exercising cookie sessions, OIDC authorization code + refresh, device code,
          TOTP, passkeys, and raw endpoint inspection against the same backend.
        </p>
        <div style={styles.inlineList}>
          <span style={sessionAuth ? styles.badge("#1a7f37", "#dafbe1") : styles.badge("#9a6700", "#fff8c5")}>
            Session: {sessionAuth ? "active" : "missing"}
          </span>
          <span style={snapshot.isAuthenticated ? styles.badge("#1a7f37", "#dafbe1") : styles.badge("#9a6700", "#fff8c5")}>
            OIDC tokens: {snapshot.isAuthenticated ? "present" : "missing"}
          </span>
        </div>
      </div>

      <RuntimeConfigCard config={config} />

      {sessionAuth && user ? (
        <Dashboard
          user={user}
          onLogout={() => {
            setSessionAuth(false);
            setUser(null);
          }}
          onSessionRefresh={checkSession}
          config={config}
        />
      ) : (
        <AuthForms onLogin={checkSession} config={config} />
      )}
    </div>
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
    return <div style={{ padding: "3rem" }}>Loading...</div>;
  }
  if (error) {
    return <div style={{ padding: "3rem", color: "#cf222e" }}>{error}</div>;
  }

  return (
    <AuthxTokenProvider client={tokenManager}>
      <AppShell />
    </AuthxTokenProvider>
  );
}

function extractError<T>(result: ApiResult<T>) {
  if (result.data && typeof result.data === "object" && "error" in result.data) {
    return String((result.data as { error?: unknown }).error ?? `Request failed (${result.status})`);
  }
  return result.text ?? `Request failed (${result.status})`;
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

function bytesToBase64Url(value: ArrayBuffer | ArrayBufferView | null | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const bytes = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function toCreationOptions(raw: unknown): CredentialCreationOptions {
  const options = raw as {
    publicKey: {
      challenge: string;
      user: { id: string; name: string; displayName: string };
      excludeCredentials?: Array<{ id: string; type: PublicKeyCredentialType }>;
    };
  };
  const user = options.publicKey.user;
  return {
    publicKey: {
      ...(options.publicKey as object),
      challenge: toArrayBuffer(base64UrlToBytes(options.publicKey.challenge)),
      user: {
        ...user,
        id: toArrayBuffer(base64UrlToBytes(user.id)),
      } as PublicKeyCredentialUserEntity,
      excludeCredentials: options.publicKey.excludeCredentials?.map((credential) => ({
        ...credential,
        id: toArrayBuffer(base64UrlToBytes(credential.id)),
      })) as PublicKeyCredentialDescriptor[] | undefined,
    } as PublicKeyCredentialCreationOptions,
  };
}

function toRequestOptions(raw: unknown): CredentialRequestOptions {
  const options = raw as {
    mediation?: CredentialMediationRequirement;
    publicKey: {
      challenge: string;
      allowCredentials?: Array<{ id: string; type: PublicKeyCredentialType }>;
    };
  };
  return {
    mediation: options.mediation,
    publicKey: {
      ...(options.publicKey as object),
      challenge: toArrayBuffer(base64UrlToBytes(options.publicKey.challenge)),
      allowCredentials: options.publicKey.allowCredentials?.map((credential) => ({
        ...credential,
        id: toArrayBuffer(base64UrlToBytes(credential.id)),
      })) as PublicKeyCredentialDescriptor[] | undefined,
    } as PublicKeyCredentialRequestOptions,
  };
}

async function runPasskeyRegistration(options: unknown) {
  const credential = (await navigator.credentials.create(toCreationOptions(options))) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error("Passkey registration returned no credential");
  }
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bytesToBase64Url(response.attestationObject),
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      transports: (response as { getTransports?: () => string[] }).getTransports?.(),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

async function runPasskeyAuthentication(options: unknown) {
  const credential = (await navigator.credentials.get(toRequestOptions(options))) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error("Passkey authentication returned no credential");
  }
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bytesToBase64Url(response.authenticatorData),
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      signature: bytesToBase64Url(response.signature),
      userHandle: bytesToBase64Url(response.userHandle),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}
