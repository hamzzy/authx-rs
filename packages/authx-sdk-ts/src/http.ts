import { AuthxErrorBody, AuthxSdkError, toAuthxSdkError } from "./errors";

export interface RequestOptions extends RequestInit {
  baseUrl?: string;
  path?: string;
}

function joinUrl(baseUrl: string | undefined, path: string | undefined): string {
  if (!baseUrl && !path) {
    throw new AuthxSdkError("either an absolute URL or baseUrl + path is required");
  }

  if (!path) {
    return baseUrl as string;
  }

  if (/^https?:\/\//.test(path)) {
    return path;
  }

  if (!baseUrl) {
    throw new AuthxSdkError("baseUrl is required for relative paths");
  }

  return new URL(path, baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`).toString();
}

export async function requestJson<T>(options: RequestOptions): Promise<T> {
  const response = await fetch(joinUrl(options.baseUrl, options.path), options);
  return parseJsonResponse<T>(response);
}

export async function requestText(options: RequestOptions): Promise<string> {
  const response = await fetch(joinUrl(options.baseUrl, options.path), options);

  if (!response.ok) {
    throw await responseToError(response);
  }

  return response.text();
}

export async function parseJsonResponse<T>(response: Response): Promise<T> {
  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json")
    ? ((await response.json()) as unknown)
    : await response.text();

  if (!response.ok) {
    throw toErrorFromPayload(response.status, payload);
  }

  return payload as T;
}

export async function responseToError(response: Response): Promise<AuthxSdkError> {
  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json")
    ? ((await response.json()) as unknown)
    : await response.text();

  return toErrorFromPayload(response.status, payload);
}

function toErrorFromPayload(status: number, payload: unknown): AuthxSdkError {
  if (typeof payload === "string") {
    return toAuthxSdkError(payload || `request failed with HTTP ${status}`, {
      status,
      details: payload,
    });
  }

  const body = (payload ?? {}) as AuthxErrorBody;
  const code = typeof body.error === "string" ? body.error : undefined;
  const message =
    (typeof body.message === "string" && body.message) ||
    (typeof body.error_description === "string" && body.error_description) ||
    (typeof body.error === "string" && body.error) ||
    `request failed with HTTP ${status}`;

  return toAuthxSdkError(message, { status, code, details: payload });
}
