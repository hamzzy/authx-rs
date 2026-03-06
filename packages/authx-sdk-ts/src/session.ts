import { requestJson } from "./http.js";

export interface SessionUser {
  id?: string;
  user_id?: string;
  email?: string;
  email_verified?: boolean;
  username?: string | null;
  [key: string]: unknown;
}

export interface SessionRecord {
  id?: string;
  session_id?: string;
  user_id?: string;
  ip_address?: string;
  org_id?: string | null;
  expires_at?: string;
  created_at?: string;
  [key: string]: unknown;
}

export interface SignInResult {
  user_id: string;
  session_id: string;
  token: string;
  [key: string]: unknown;
}

export interface SignUpResult {
  user_id: string;
  email: string;
  [key: string]: unknown;
}

export interface SessionEnvelope {
  user?: SessionUser;
  session?: SessionRecord;
  [key: string]: unknown;
}

export interface BrowserSessionClientOptions {
  baseUrl: string;
  credentials?: RequestCredentials;
  headers?: HeadersInit;
}

export interface CredentialInput {
  email: string;
  password: string;
}

export class BrowserSessionClient {
  private readonly baseUrl: string;
  private readonly credentials: RequestCredentials;
  private readonly headers?: HeadersInit;

  constructor(options: BrowserSessionClientOptions) {
    this.baseUrl = options.baseUrl;
    this.credentials = options.credentials ?? "include";
    this.headers = options.headers;
  }

  signUp(body: CredentialInput): Promise<SignUpResult> {
    return this.postJson<SignUpResult>("/auth/sign-up", body);
  }

  signIn(body: CredentialInput): Promise<SignInResult> {
    return this.postJson<SignInResult>("/auth/sign-in", body);
  }

  async signOut(): Promise<void> {
    await this.postJson<unknown>("/auth/sign-out", undefined);
  }

  async signOutAll(): Promise<void> {
    await this.postJson<unknown>("/auth/sign-out/all", undefined);
  }

  session(): Promise<SessionEnvelope> {
    return requestJson<SessionEnvelope>({
      baseUrl: this.baseUrl,
      path: "/auth/session",
      method: "GET",
      credentials: this.credentials,
      headers: this.headers,
    });
  }

  sessions(): Promise<SessionRecord[]> {
    return requestJson<SessionRecord[]>({
      baseUrl: this.baseUrl,
      path: "/auth/sessions",
      method: "GET",
      credentials: this.credentials,
      headers: this.headers,
    });
  }

  private postJson<T>(path: string, body: unknown): Promise<T> {
    return requestJson<T>({
      baseUrl: this.baseUrl,
      path,
      method: "POST",
      credentials: this.credentials,
      headers: {
        "Content-Type": "application/json",
        ...(this.headers ?? {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }
}
