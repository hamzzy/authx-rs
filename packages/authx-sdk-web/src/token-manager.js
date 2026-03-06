import { AuthxTokenManagerError } from "./errors.js";
export class AuthxTokenManager {
    constructor(options) {
        this.listeners = new Set();
        this.current = null;
        this.started = false;
        this.storage = options.storage;
        this.refreshHandler = options.refresh;
        this.autoRefresh = options.autoRefresh ?? true;
        this.refreshWindowMs = options.refreshWindowMs ?? 30000;
        this.clearOnRefreshError = options.clearOnRefreshError ?? true;
        this.now = options.now ?? (() => Date.now());
        this.fetchImpl = options.fetch ?? globalThis.fetch;
        this.onRefreshError = options.onRefreshError;
    }
    async start() {
        if (!this.started) {
            this.current = await this.storage.load();
            this.started = true;
            this.scheduleRefresh();
            this.emit();
        }
        return this.getSnapshot();
    }
    stop() {
        this.clearRefreshTimer();
    }
    subscribe(listener) {
        this.listeners.add(listener);
        return () => {
            this.listeners.delete(listener);
        };
    }
    getSnapshot() {
        return {
            tokens: this.current ? { ...this.current } : null,
            isAuthenticated: Boolean(this.current?.accessToken),
            isRefreshing: Boolean(this.refreshPromise),
            error: this.lastError,
        };
    }
    async setTokens(tokens) {
        await this.start();
        this.current = tokens ? { ...tokens } : null;
        this.lastError = undefined;
        await this.storage.save(this.current);
        this.scheduleRefresh();
        this.emit();
        return this.getSnapshot();
    }
    async setTokenResponse(response, options = {}) {
        return this.setTokens(tokenResponseToStoredState(response, {
            now: options.now ?? this.now(),
            previous: this.current,
            preserveRefreshToken: options.preserveRefreshToken,
        }));
    }
    async clear() {
        return this.setTokens(null);
    }
    async getAccessToken(minValidityMs = 0) {
        await this.start();
        if (!this.current) {
            return null;
        }
        if (this.current.expiresAt <= this.now()) {
            if (!this.current.refreshToken || !this.refreshHandler) {
                await this.clear();
                return null;
            }
            return (await this.refresh()).accessToken;
        }
        if (this.expiresWithin(minValidityMs)) {
            if (!this.current.refreshToken || !this.refreshHandler) {
                return this.current.accessToken;
            }
            return (await this.refresh()).accessToken;
        }
        return this.current.accessToken;
    }
    async refresh() {
        await this.start();
        if (!this.current?.refreshToken) {
            throw new AuthxTokenManagerError("refresh token is not available");
        }
        if (!this.refreshHandler) {
            throw new AuthxTokenManagerError("refresh handler is not configured");
        }
        if (this.refreshPromise) {
            return this.refreshPromise;
        }
        this.refreshPromise = (async () => {
            const response = await this.refreshHandler(this.current);
            const next = tokenResponseToStoredState(response, {
                now: this.now(),
                previous: this.current,
            });
            await this.setTokens(next);
            return next;
        })()
            .catch(async (error) => {
            this.lastError = error;
            this.onRefreshError?.(error);
            if (this.clearOnRefreshError) {
                await this.setTokens(null);
            }
            else {
                this.scheduleRefresh();
                this.emit();
            }
            throw error;
        })
            .finally(() => {
            this.refreshPromise = undefined;
            this.emit();
        });
        this.emit();
        return this.refreshPromise;
    }
    async fetch(input, init, options = {}) {
        await this.start();
        const request = new Request(input, init);
        const token = await this.getAccessToken(options.minValidityMs ?? this.refreshWindowMs);
        let response = await this.send(request.clone(), token);
        if (response.status === 401 &&
            (options.retryOnUnauthorized ?? true) &&
            this.current?.refreshToken &&
            this.refreshHandler) {
            try {
                const refreshed = await this.refresh();
                response = await this.send(request.clone(), refreshed.accessToken);
            }
            catch {
                return response;
            }
        }
        return response;
    }
    async send(request, accessToken) {
        const headers = new Headers(request.headers);
        if (accessToken && !headers.has("Authorization")) {
            headers.set("Authorization", `Bearer ${accessToken}`);
        }
        return this.fetchImpl(new Request(request, { headers }));
    }
    expiresWithin(windowMs) {
        if (!this.current) {
            return false;
        }
        return this.current.expiresAt - this.now() <= windowMs;
    }
    scheduleRefresh() {
        this.clearRefreshTimer();
        if (!this.autoRefresh ||
            !this.current?.refreshToken ||
            !this.refreshHandler) {
            return;
        }
        const delay = Math.max(this.current.expiresAt - this.now() - this.refreshWindowMs, 0);
        this.refreshTimer = setTimeout(() => {
            void this.refresh().catch(() => undefined);
        }, delay);
    }
    clearRefreshTimer() {
        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
            this.refreshTimer = undefined;
        }
    }
    emit() {
        const snapshot = this.getSnapshot();
        for (const listener of this.listeners) {
            listener(snapshot);
        }
    }
}
export function tokenResponseToStoredState(response, options = {}) {
    const now = options.now ?? Date.now();
    if (!response.access_token) {
        throw new AuthxTokenManagerError("access_token is required");
    }
    if (!response.token_type) {
        throw new AuthxTokenManagerError("token_type is required");
    }
    if (typeof response.expires_in !== "number" || !Number.isFinite(response.expires_in)) {
        throw new AuthxTokenManagerError("expires_in must be a finite number");
    }
    const refreshToken = response.refresh_token ??
        ((options.preserveRefreshToken ?? true) ? options.previous?.refreshToken : undefined);
    return {
        accessToken: response.access_token,
        tokenType: response.token_type,
        expiresAt: now + Math.max(response.expires_in, 0) * 1000,
        refreshToken,
        scope: response.scope,
        idToken: response.id_token,
    };
}
