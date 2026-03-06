import { requestJson } from "./http.js";
import type { OidcTokenResponse } from "./oidc.js";

export interface DeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
  [key: string]: unknown;
}

export interface DeviceAuthorizationOptions {
  endpoint: string;
  clientId: string;
  scope?: string;
}

export interface PollDeviceTokenOptions {
  tokenEndpoint: string;
  clientId: string;
  deviceCode: string;
  clientSecret?: string;
}

export async function startDeviceAuthorization(
  options: DeviceAuthorizationOptions,
): Promise<DeviceAuthorizationResponse> {
  const body = new URLSearchParams({
    client_id: options.clientId,
  });

  if (options.scope) {
    body.set("scope", options.scope);
  }

  return requestJson<DeviceAuthorizationResponse>({
    path: options.endpoint,
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
}

export async function pollDeviceToken(
  options: PollDeviceTokenOptions,
): Promise<OidcTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    client_id: options.clientId,
    device_code: options.deviceCode,
  });

  if (options.clientSecret) {
    body.set("client_secret", options.clientSecret);
  }

  return requestJson<OidcTokenResponse>({
    path: options.tokenEndpoint,
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
}
