import { AuthxTokenManagerError } from "./errors.js";
export function createOidcTokenRefresher(options) {
    return async (tokens) => {
        if (!tokens.refreshToken) {
            throw new AuthxTokenManagerError("refresh token is required to perform token refresh");
        }
        const body = new URLSearchParams({
            grant_type: "refresh_token",
            client_id: options.clientId,
            refresh_token: tokens.refreshToken,
        });
        if (options.clientSecret) {
            body.set("client_secret", options.clientSecret);
        }
        if (options.scope) {
            body.set("scope", options.scope);
        }
        const fetchImpl = options.fetch ?? globalThis.fetch;
        const response = await fetchImpl(options.tokenEndpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                ...(options.headers ?? {}),
            },
            body,
        });
        const contentType = response.headers.get("content-type") ?? "";
        const payload = contentType.includes("application/json")
            ? (await response.json())
            : await response.text();
        if (!response.ok) {
            const message = typeof payload === "string" && payload
                ? payload
                : "OIDC token refresh request failed";
            throw new AuthxTokenManagerError(message, { cause: payload });
        }
        return payload;
    };
}
